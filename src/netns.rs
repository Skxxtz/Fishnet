use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, Gid, Uid, User, fork, getgrouplist, setgid, setgroups, setuid};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const NETNS_DIR: &str = "/var/run/netns";

fn ns_path(name: &str) -> PathBuf {
    PathBuf::from(NETNS_DIR).join(name)
}

pub fn exists(name: &str) -> bool {
    ns_path(name).exists()
}

/// True if `path` currently shows up as a mount point in this process's mount namespace.
///
/// We can't use "compare st_dev to the parent's" here: /var/run/netns is bind-mounted onto
/// *itself*, and a self bind mount shares the exact same tmpfs superblock as its target, so its
/// device id never changes. Reading /proc/self/mountinfo directly is the reliable way to tell.
fn is_mountpoint(path: &Path) -> bool {
    let Ok(canonical) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mountinfo.lines().any(|line| {
        // Format: ID parent-ID major:minor root mount-point options ...
        // Field 5 (0-indexed 4) is the mount point.
        line.split_whitespace()
            .nth(4)
            .is_some_and(|mp| Path::new(mp) == canonical)
    })
}

/// Creates a persistent, bind-mounted network namespace file at /var/run/netns/<name>, using unshare(2) +
/// mount(2).
pub fn create(name: &str) -> Result<()> {
    fs::create_dir_all(NETNS_DIR).context("mkdir /var/run/netns")?;

    // Idempotent:
    // (1) bind-mount (and only once) if /var/run/netns isn't
    // already its own mountpoint.
    // (2) Mark it MS_PRIVATE right after, so mount/unmount activity under it (netns files,
    // resolv.conf binds from `exec`) doesn't propagate into the host's shared mount tree that
    // systemd watches.
    if !is_mountpoint(Path::new(NETNS_DIR)) {
        mount(
            Some(NETNS_DIR),
            NETNS_DIR,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("bind mount /var/run/netns")?;
        mount(
            None::<&str>,
            NETNS_DIR,
            None::<&str>,
            MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .context("mark /var/run/netns private")?;
    }

    let target = ns_path(name);
    File::create(&target).context("create netns file")?;

    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            let result = (|| -> Result<()> {
                unshare(CloneFlags::CLONE_NEWNET).context("unshare(CLONE_NEWNET)")?;
                mount(
                    Some("/proc/self/ns/net"),
                    &target,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .context("bind mount netns")?;
                Ok(())
            })();
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).context("waitpid")?;
            anyhow::ensure!(
                matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                "child failed to create namespace"
            );
        }
    }
    Ok(())
}

/// Idempotent: a namespace that's already gone is success, not an error.
pub fn delete(name: &str) -> Result<()> {
    use nix::mount::{MntFlags, umount2};
    let target = ns_path(name);
    if target.exists() {
        loop {
            match umount2(&target, MntFlags::MNT_DETACH) {
                Ok(()) => continue,
                Err(_) => break,
            }
        }
        let _ = fs::remove_file(&target);
    }

    // Also unwind the /var/run/netns bind mount itself. `create()` is
    // idempotent going forward, but this clears any duplicate layers left
    // over from before that fix (or from any other stacking), so `up`
    // starts from a clean single mount rather than accumulating forever.
    while is_mountpoint(Path::new(NETNS_DIR)) {
        match umount2(NETNS_DIR, MntFlags::MNT_DETACH) {
            Ok(()) => continue,
            Err(_) => break,
        }
    }
    Ok(())
}

/// True if a WireGuard-style interface (name prefix "wg") exists inside
/// namespace `name`. Used as the exec-time kill switch: no such interface,
/// no traffic leaves the namespace via `fishnet exec`.
pub fn has_vpn_interface(name: &str) -> Result<bool> {
    let name = name.to_string();
    std::thread::spawn(move || -> Result<bool> {
        enter(&name)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let (conn, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(conn);
            let mut links = handle.link().get().execute();
            while let Some(link) = links.try_next().await? {
                for attr in &link.attributes {
                    if let LinkAttribute::IfName(n) = attr {
                        if n.starts_with("wg") {
                            return anyhow::Ok(true);
                        }
                    }
                }
            }
            anyhow::Ok(false)
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("has_vpn_interface thread panicked"))?
}

/// Ensures /etc/netns/<name>/resolv.conf exists (seeded from the host's
/// current resolv.conf on first use), following the same convention `ip
/// netns exec` uses. Returns its path.
fn ensure_netns_resolv_conf(name: &str) -> Result<PathBuf> {
    let dir = PathBuf::from("/etc/netns").join(name);
    fs::create_dir_all(&dir).context("mkdir /etc/netns/<name>")?;
    let path = dir.join("resolv.conf");
    if !path.exists() {
        let contents = fs::read("/etc/resolv.conf").unwrap_or_default();
        fs::write(&path, contents).context("seed netns resolv.conf")?;
    }
    Ok(path)
}

/// Switch the current thread into namespace `name`. To route traffic through ns.
pub fn enter(name: &str) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(ns_path(name))
        .context("open netns file")?;
    setns(&file, CloneFlags::CLONE_NEWNET).context("setns")?;
    Ok(())
}

pub fn open_fd(name: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .open(ns_path(name))
        .context("open netns file")
}

/// Who the spawned command runs as. Decided by the subcommand, never by argv.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunAs {
    /// Stay root. Only for `connect`: the VPN client must configure interfaces and routes.
    Root,
    /// Drop to the user who invoked sudo. For `exec` (and `status`): apps never keep root.
    Caller,
}

#[derive(Clone, Copy)]
pub struct ExecOpts {
    pub run_as: RunAs,
    /// Double-fork + setsid + null stdio: the command outlives us and doesn't hold our
    /// terminal. For GUI apps / launchers. Foreground (default) keeps stdio and exit code.
    pub detach: bool,
}

impl ExecOpts {
    pub fn root() -> Self {
        Self { run_as: RunAs::Root, detach: false }
    }
    pub fn caller(detach: bool) -> Self {
        Self { run_as: RunAs::Caller, detach }
    }
}

/// The invoking user, fully resolved BEFORE fork so that `pre_exec` only has to make plain
/// syscalls (no allocation, no NSS lookups, which aren't async-signal-safe).
struct Caller {
    user: User,
    gid: Gid,
    groups: Vec<Gid>,
}

fn sudo_caller() -> Result<Caller> {
    let uid: u32 = std::env::var("SUDO_UID")
        .context("SUDO_UID not set — run this via `sudo` from your own user account")?
        .parse()
        .context("parse SUDO_UID")?;
    let gid: u32 = std::env::var("SUDO_GID")
        .context("SUDO_GID not set")?
        .parse()
        .context("parse SUDO_GID")?;
    // Fail closed: never "drop" to root, and never silently stay root.
    anyhow::ensure!(
        uid != 0,
        "refusing to run this command as root; invoke sudo from a normal user account"
    );

    let user = User::from_uid(Uid::from_raw(uid))
        .context("look up SUDO_UID")?
        .with_context(|| format!("no passwd entry for uid {uid}"))?;
    let gid = Gid::from_raw(gid);
    let name = CString::new(user.name.as_str()).context("user name contains NUL")?;
    let groups = getgrouplist(&name, gid).context("getgrouplist")?;
    Ok(Caller { user, gid, groups })
}

/// Fix the vars sudo forces to root's identity (HOME/USER/LOGNAME/MAIL), restore the
/// desktop-session vars sudo's env_reset strips, and drop sudo's own bookkeeping vars.
fn apply_caller_env(command: &mut Command, c: &Caller) {
    let uid = c.user.uid.as_raw();
    let home = c.user.dir.display().to_string();
    let runtime_dir = format!("/run/user/{uid}");

    command.env("HOME", &home);
    command.env("USER", &c.user.name);
    command.env("LOGNAME", &c.user.name);
    if std::env::var_os("MAIL").is_some() {
        command.env("MAIL", format!("/var/mail/{}", c.user.name));
    }

    // sudo's env_reset strips these before we ever see them, so "inherited" is
    // indistinguishable from "unset" — use the inherited value if present (env_keep,
    // `sudo -E`), otherwise the normal per-user default.
    let keep_or_default = |key: &str, default: String| std::env::var(key).unwrap_or(default);
    command.env(
        "XDG_RUNTIME_DIR",
        keep_or_default("XDG_RUNTIME_DIR", runtime_dir.clone()),
    );
    command.env("DISPLAY", keep_or_default("DISPLAY", ":0".to_string()));
    command.env(
        "XAUTHORITY",
        keep_or_default("XAUTHORITY", format!("{home}/.Xauthority")),
    );
    command.env(
        "WAYLAND_DISPLAY",
        keep_or_default("WAYLAND_DISPLAY", "wayland-0".to_string()),
    );
    command.env(
        "DBUS_SESSION_BUS_ADDRESS",
        keep_or_default(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_dir}/bus"),
        ),
    );

    for var in ["SUDO_UID", "SUDO_GID", "SUDO_USER", "SUDO_COMMAND"] {
        command.env_remove(var);
    }
}

/// Run `cmd` inside namespace `name`. Returns the exit code (always 0 when detached).
pub fn exec_in(name: &str, cmd: &[String], opts: ExecOpts) -> Result<i32> {
    anyhow::ensure!(!cmd.is_empty(), "no command given");

    let ns_file = open_fd(name)?;
    let resolv_conf = ensure_netns_resolv_conf(name)?;

    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]);

    let caller = match opts.run_as {
        RunAs::Caller => {
            let c = sudo_caller()?;
            apply_caller_env(&mut command, &c);
            Some(c)
        }
        RunAs::Root => None,
    };

    let detach = opts.detach;
    if detach {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }

    // SAFETY: pre_exec runs in the forked child between fork() and exec(). Everything it needs
    // (fd, paths, uid/gid, group list) was computed above, so it only makes plain syscalls.
    // Order matters: setns and the mounts need root, so the uid/gid drop comes last.
    unsafe {
        command.pre_exec(move || {
            let os = io::Error::from;

            setns(&ns_file, CloneFlags::CLONE_NEWNET).map_err(os)?;

            // Private mount namespace with our per-netns resolv.conf bound over
            // /etc/resolv.conf, so `resolvconf` (run by a VPN client inside the namespace)
            // rewrites only the namespace's view of DNS, never the host's real file.
            unshare(CloneFlags::CLONE_NEWNS).map_err(os)?;
            mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            )
            .map_err(os)?;
            mount(
                Some(resolv_conf.as_path()),
                "/etc/resolv.conf",
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(os)?;

            if let Some(c) = &caller {
                setgroups(&c.groups).map_err(os)?;
                setgid(c.gid).map_err(os)?;
                setuid(c.user.uid).map_err(os)?;
            }

            // Detach last, so setup failures above are reported to the parent through
            // std's exec-error pipe. The intermediate child exits immediately, the
            // grandchild is adopted by PID 1 and has no controlling terminal.
            if detach {
                match libc::fork() {
                    -1 => return Err(io::Error::last_os_error()),
                    0 => {
                        libc::setsid();
                    }
                    _ => libc::_exit(0),
                }
            }
            Ok(())
        });
    }

    // Detached: this waits only for the intermediate child (exit 0), and still returns
    // spawn/exec errors from the grandchild via the pipe.
    let status = command.status().context("spawn command")?;
    if detach {
        return Ok(0);
    }
    Ok(status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1))
}
