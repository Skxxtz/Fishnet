use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, fork};
use std::fs::{self, File, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Spawn `cmd` as a normal child process, joined to namespace `name`, and
/// — if this process was invoked via sudo — running as the real invoking
/// user with a properly reconstructed desktop environment, rather than
/// sudo's sanitized one.
pub fn exec_in(name: &str, cmd: &[String]) -> Result<()> {
    anyhow::ensure!(!cmd.is_empty(), "no command given");

    let ns_file = open_fd(name)?;
    let resolv_conf = ensure_netns_resolv_conf(name)?;

    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    let cmd_needs_root = cmd[0] == "sudo";

    // (1) fix the vars sudo forces to root's identity (HOME/USER/LOGNAME, MAIL) and the
    // desktop-session vars sudo's env_reset strips (DISPLAY/XAUTHORITY/WAYLAND_DISPLAY/
    // DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR), and (2) drop sudo's own bookkeeping vars so they
    // don't leak into the child.
    let mut sudo_user_info: Option<(u32, u32, nix::unistd::User)> = None;
    if !cmd_needs_root {
        if let (Ok(uid_str), Ok(gid_str)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            let uid: u32 = uid_str.parse().context("parse SUDO_UID")?;
            let gid: u32 = gid_str.parse().context("parse SUDO_GID")?;

            if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
                let home = user.dir.display().to_string();
                let runtime_dir = format!("/run/user/{uid}");

                command.env("HOME", &home);
                command.env("USER", &user.name);
                command.env("LOGNAME", &user.name);
                if std::env::var_os("MAIL").is_some() {
                    command.env("MAIL", format!("/var/mail/{}", user.name));
                }

                // sudo's env_reset strips these before we ever see them, so
                // "inherited" is indistinguishable from "unset" here — use
                // the inherited value if present (e.g. env_keep in sudoers,
                // or `sudo -E`), otherwise fall back to the normal per-user
                // default so GUI apps still find a display/session bus.
                let keep_or_default =
                    |key: &str, default: String| std::env::var(key).unwrap_or(default);
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

                sudo_user_info = Some((uid, gid, user));
            }
        }
    }

    // SAFETY: pre_exec runs in the forked child between fork() and exec(), still fully root at this
    // point. We do setns() FIRST, only THEN drop to the target uid/gid ourselves — doing both steps
    // explicitly here, in this order, rather than mixing our pre_exec with Command's separate
    // built-in .uid()/.gid() machinery, removes any ambiguity about which happens first.
    unsafe {
        command.pre_exec(move || {
            setns(&ns_file, CloneFlags::CLONE_NEWNET)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

            // Give this process its own mount namespace and bind our
            // per-netns resolv.conf over /etc/resolv.conf, so tools like
            // `resolvconf` (run by a VPN client inside fishnetns) rewrite
            // only the namespace's view of DNS, never the host's real file.
            unshare(CloneFlags::CLONE_NEWNS)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            mount(
                Some(resolv_conf.as_path()),
                "/etc/resolv.conf",
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

            if let Some((uid, gid, ref user)) = sudo_user_info {
                let _ = nix::unistd::initgroups(
                    &std::ffi::CString::new(user.name.as_str()).unwrap(),
                    nix::unistd::Gid::from_raw(gid),
                );
                nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            }
            Ok(())
        });
    }

    let status = command.status().context("spawn command")?;
    anyhow::ensure!(status.success(), "command exited with {status}");
    Ok(())
}
