use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use crate::netns;

const VETH_HOST: &str = "vh0";
const VETH_NS: &str = "vn0";

const HOST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 1, 1);
const NS_VETH_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 1, 2);
const PREFIX: u8 = 24;

/// Unique Local Address (ULA) range for the veth link, the IPv6 equivalent of the private
/// 10.200.1.0/24 range used for IPv4 — not globally routable on its own, gets NAT66'd through the
/// host's real uplink just like IPv4 does. This gives the namespace baseline IPv6 connectivity so a
/// VPN provider's own IPv6 routes have something to override, instead of the namespace
/// silently having no IPv6 path at all (or worse, an unmanaged one that leaks around the VPN).
pub const HOST_ADDR6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xfefe, 0xcafe, 0, 0, 0, 0, 1);
const NS_VETH_ADDR6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xfefe, 0xcafe, 0, 0, 0, 0, 2);
pub const PREFIX6: u8 = 64;

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links
        .try_next()
        .await?
        .with_context(|| format!("link {name} not found"))?;
    Ok(link.header.index)
}

/// Delete the host-side veth link. Deleting one end of a veth pair removes
/// the other end too. Idempotent: fine if vh0 doesn't exist.
pub async fn teardown_host_side() -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    if let Ok(idx) = link_index(&handle, VETH_HOST).await {
        handle.link().del(idx).execute().await.context("delete vh0")?;
    }
    Ok(())
}

/// Root-namespace side: create the veth pair, address the host end (both
/// v4 and v6), move the peer into `ns`.
pub async fn setup_host_side(ns: &str) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    handle
        .link()
        .add()
        .veth(VETH_HOST.into(), VETH_NS.into())
        .execute()
        .await
        .context("create veth pair")?;

    let host_idx = link_index(&handle, VETH_HOST).await?;
    handle
        .address()
        .add(host_idx, IpAddr::V4(HOST_ADDR), PREFIX)
        .execute()
        .await
        .context("v4 addr on host veth")?;
    handle
        .address()
        .add(host_idx, IpAddr::V6(HOST_ADDR6), PREFIX6)
        .execute()
        .await
        .context("v6 addr on host veth")?;
    handle.link().set(host_idx).up().execute().await?;

    let ns_file = netns::open_fd(ns)?;
    let ns_idx = link_index(&handle, VETH_NS).await?;
    handle
        .link()
        .set(ns_idx)
        .setns_by_fd(ns_file.as_raw_fd())
        .execute()
        .await
        .context("move veth peer into netns")?;

    Ok(())
}

/// Inside the namespace: address the veth peer (v4 + v6), bring up
/// loopback, and point the default routes (v4 + v6) at the host.
///
/// Runs on a dedicated OS thread: setns() only affects the calling thread,
/// so doing this on a throwaway thread (joined before returning) keeps the
/// caller's own thread — and everything it does afterward, like firewall
/// setup — in the HOST namespace, not fishnetns.
pub fn setup_ns_side(ns: &str) -> Result<()> {
    let ns = ns.to_string();
    std::thread::spawn(move || -> Result<()> {
        netns::enter(&ns)?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let (conn, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(conn);

            let ns_idx = link_index(&handle, VETH_NS).await?;
            handle
                .address()
                .add(ns_idx, IpAddr::V4(NS_VETH_ADDR), PREFIX)
                .execute()
                .await
                .context("v4 addr in namespace")?;
            handle
                .address()
                .add(ns_idx, IpAddr::V6(NS_VETH_ADDR6), PREFIX6)
                .execute()
                .await
                .context("v6 addr in namespace")?;
            handle.link().set(ns_idx).up().execute().await?;

            let lo_idx = link_index(&handle, "lo").await?;
            handle.link().set(lo_idx).up().execute().await?;

            handle
                .route()
                .add()
                .v4()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(HOST_ADDR)
                .execute()
                .await
                .context("v4 default route")?;
            handle
                .route()
                .add()
                .v6()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .gateway(HOST_ADDR6)
                .execute()
                .await
                .context("v6 default route")?;

            anyhow::Ok(())
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("setup_ns_side thread panicked"))?
}
