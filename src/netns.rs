use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};
use std::fs::{self, File, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const NETNS_DIR: &str = "/var/run/netns";

fn ns_path(name: &str) -> PathBuf {
    PathBuf::from(NETNS_DIR).join(name)
}

/// Creates a persistent, bind-mounted network namespace file at /var/run/netns/<name>, using unshare(2) +
/// mount(2).
pub fn create(name: &str) -> Result<()> {
    fs::create_dir_all(NETNS_DIR).context("mkdir /var/run/netns")?;

    let _ = mount(
        Some(NETNS_DIR),
        NETNS_DIR,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    );

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

pub fn delete(name: &str) -> Result<()> {
    use nix::mount::{umount2, MntFlags};
    let target = ns_path(name);
    loop {
        match umount2(&target, MntFlags::MNT_DETACH) {
            Ok(()) => continue,
            Err(_) => break,
        }
    }
    fs::remove_file(&target).context("remove netns file")?;
    Ok(())
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

    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]);

    let mut sudo_user_info: Option<(u32, u32, nix::unistd::User)> = None;
    if let (Ok(uid_str), Ok(gid_str)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        let uid: u32 = uid_str.parse().context("parse SUDO_UID")?;
        let gid: u32 = gid_str.parse().context("parse SUDO_GID")?;

        let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
        command.env_clear();

        if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
            let home = user.dir.display().to_string();
            let runtime_dir = format!("/run/user/{uid}");

            command.env("HOME", &home);
            command.env("USER", &user.name);
            command.env("LOGNAME", &user.name);
            command.env("PATH", &path);
            command.env("XDG_RUNTIME_DIR", &runtime_dir);

            let defaults = [
                ("DISPLAY", ":0".to_string()),
                ("XAUTHORITY", format!("{home}/.Xauthority")),
                ("WAYLAND_DISPLAY", "wayland-0".to_string()),
                ("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={runtime_dir}/bus")),
            ];
            for (key, default) in defaults {
                let value = std::env::var(key).unwrap_or(default);
                command.env(key, value);
            }

            sudo_user_info = Some((uid, gid, user));
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
