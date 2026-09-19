mod firewall;
mod netns;
mod veth;

use anyhow::Result;
use clap::{Parser, Subcommand};
use netns::ExecOpts;
use std::net::{Ipv4Addr, Ipv6Addr};

const NS: &str = "fishnetns";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Up,
    /// Run a command as root inside the namespace, without the VPN kill switch — for the VPN
    /// client's own connect command, which has to reach the internet before any tunnel exists.
    Connect {
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run a command as the invoking user inside the namespace (requires an active VPN).
    Exec {
        /// Detach from the terminal and return immediately (for GUI apps / launchers).
        #[arg(short, long)]
        detach: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    Status,
    Down,
}

/// Idempotent teardown, shared by `down` and by `up` when re-creating a
/// stale namespace.
fn down() -> Result<()> {
    // Kill everything still running in the namespace first (detached apps, the VPN client),
    // so nothing keeps talking while the plumbing is removed.
    netns::kill_all(NS);
    let _ = firewall::teardown();
    let rt = tokio::runtime::Runtime::new()?;
    let _ = rt.block_on(veth::teardown_host_side());
    netns::delete(NS)
}

fn exit_with(code: i32) -> Result<()> {
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Up => {
            if netns::exists(NS) {
                // Rebuild cleanly rather than fail on stale state (EEXIST
                // on the veth, leftover nftables table, etc).
                down()?;
            }
            netns::create(NS)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(veth::setup_host_side(NS))?;

            let uplink = rt.block_on(firewall::detect_uplink())?;
            firewall::enable_ip_forward()?;
            firewall::setup_nat_and_forward(
                veth::VETH_HOST,
                &uplink,
                Ipv4Addr::new(10, 200, 1, 0),
                24,
                Ipv6Addr::new(0xfd00, 0xfefe, 0xcafe, 0, 0, 0, 0, 0),
                64,
            )?;

            veth::setup_ns_side(NS)?;

            println!("{NS} is up, routed to the internet via {uplink}.");
            Ok(())
        }
        Cmd::Connect { command } => {
            anyhow::ensure!(
                netns::exists(NS),
                "fishnetns is down — run `fishnet up` first"
            );
            exit_with(netns::exec_in(NS, &command, ExecOpts::root())?)
        }
        Cmd::Exec { detach, command } => {
            anyhow::ensure!(
                netns::exists(NS),
                "fishnetns is down — run `fishnet up` first"
            );
            if !netns::has_vpn_interface(NS)? {
                anyhow::bail!(
                    "kill switch: fishnetns's default route still points at the plain NAT \
                     fallback (no VPN has taken it over), refusing to run `{}`. Connect your \
                     VPN first with `fishnet connect -- <command>`.",
                    command.join(" ")
                );
            }
            exit_with(netns::exec_in(NS, &command, ExecOpts::caller(detach))?)
        }
        Cmd::Status => {
            if !netns::exists(NS) {
                println!("fishnetns is down.");
                return Ok(());
            }
            println!("fishnetns is up.");

            let rt = tokio::runtime::Runtime::new()?;

            println!(
                "veth (vh0): {}",
                if rt.block_on(veth::host_link_exists()) {
                    "up"
                } else {
                    "missing"
                }
            );

            match rt.block_on(firewall::detect_uplink()) {
                Ok(uplink) => println!("uplink: {uplink}"),
                Err(e) => println!("uplink: unknown ({e})"),
            }

            let vpn_up = netns::has_vpn_interface(NS)?;
            println!(
                "vpn: {}",
                if vpn_up {
                    "connected (default route left the NAT fallback)"
                } else {
                    "NOT connected — exec is blocked (kill switch)"
                }
            );

            if vpn_up {
                // Quick reachability check from inside the namespace —
                // reuses the exact same exec path as normal commands, just
                // with curl and a short timeout so `status` doesn't hang.
                match netns::exec_in(
                    NS,
                    &[
                        "curl".into(),
                        "-s".into(),
                        "--max-time".into(),
                        "3".into(),
                        "-4".into(),
                        "ifconfig.me".into(),
                    ],
                    ExecOpts::caller(false),
                ) {
                    Ok(0) => eprintln!(),
                    Ok(code) => println!("(reachability check failed: curl exited with {code})"),
                    Err(e) => println!("(couldn't reach the internet from inside fishnetns: {e})"),
                }
            }
            Ok(())
        }
        Cmd::Down => down(),
    }
}
