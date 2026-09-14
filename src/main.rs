mod firewall;
mod netns;
mod veth;

use anyhow::Result;
use clap::{Parser, Subcommand};
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
    Exec {
        #[arg(last = true)]
        command: Vec<String>,
    },
    Status,
    Down,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Up => {
            netns::create(NS)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(veth::setup_host_side(NS))?;

            let uplink = rt.block_on(firewall::detect_uplink())?;
            firewall::enable_ip_forward()?;
            firewall::setup_nat_and_forward(
                "vh0",
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
        Cmd::Exec { command } => netns::exec_in(NS, &command),
        Cmd::Status => {
            if !netns::exists(NS) {
                println!("fishnetns is down.");
                return Ok(());
            }
            println!("fishnetns is up.");

            // Quick reachability check from inside the namespace — reuses
            // the exact same exec path as normal commands, just with curl
            // and a short timeout so `status` doesn't hang if something's
            // wrong.
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
            ) {
                Ok(()) => {
                    eprintln!("")
                }
                Err(e) => println!("(couldn't reach the internet from inside fishnetns: {e})"),
            }
            Ok(())
        }
        Cmd::Down => {
            let _ = firewall::teardown();
            let rt = tokio::runtime::Runtime::new()?;
            let _ = rt.block_on(veth::teardown_host_side());
            netns::delete(NS)
        }
    }
}
