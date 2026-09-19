use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::route::RouteAttribute;
use rustables::expr::{
    Bitwise, Cmp, CmpOp, Conntrack, ConntrackKey, ConnTrackState, Immediate, Masquerade, Meta,
    MetaType, VerdictKind,
};
use rustables::{Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// Identify default network interface route that connects to the internet. Instead of relying on
// `eth0` or `wlan0`. 
pub async fn detect_uplink() -> Result<String> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let mut routes = handle.route().get(rtnetlink::IpVersion::V4).execute();
    while let Some(route) = routes.try_next().await? {
        let has_destination = route
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::Destination(_)));
        let is_default = route.header.destination_prefix_length == 0 && !has_destination;
        if !is_default {
            continue;
        }

        let oif = route.attributes.iter().find_map(|a| {
            if let RouteAttribute::Oif(idx) = a {
                Some(*idx)
            } else {
                None
            }
        });
        if let Some(oif) = oif {
            let mut links = handle.link().get().match_index(oif).execute();
            if let Some(link) = links.try_next().await? {
                for attr in &link.attributes {
                    if let LinkAttribute::IfName(n) = attr {
                        return Ok(n.clone());
                    }
                }
            }
        }
    }
    anyhow::bail!("no default route found — can't auto-detect uplink interface")
}

const STATE_DIR: &str = "/run/fishnet";
const SYSCTL_STATE: &str = "/run/fishnet/sysctl.saved";
const FORWARD_SYSCTLS: [&str; 2] = [
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];

/// Enable IPv4 AND IPv6 forwarding. The original values are saved under /run/fishnet (tmpfs, so
/// a reboot clears it together with the sysctls) and put back by `restore_ip_forward` on `down`.
pub fn enable_ip_forward() -> Result<()> {
    // Save only once: if an earlier run crashed before `down`, the file still holds the true
    // originals and must not be overwritten with our own "1".
    if !Path::new(SYSCTL_STATE).exists() {
        let mut saved = String::new();
        for path in FORWARD_SYSCTLS {
            let old = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
            saved.push_str(&format!("{path}={}\n", old.trim()));
        }
        std::fs::create_dir_all(STATE_DIR).context("mkdir /run/fishnet")?;
        std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o700))
            .context("chmod /run/fishnet")?;
        std::fs::write(SYSCTL_STATE, saved).context("save sysctl state")?;
    }
    for path in FORWARD_SYSCTLS {
        std::fs::write(path, b"1").with_context(|| format!("enable {path}"))?;
    }
    Ok(())
}

/// Put the forwarding sysctls back to what they were before `enable_ip_forward`. No-op if
/// nothing was saved. Only ever writes to the known sysctl paths, whatever the file says.
pub fn restore_ip_forward() -> Result<()> {
    let Ok(saved) = std::fs::read_to_string(SYSCTL_STATE) else {
        return Ok(());
    };
    let mut failure = None;
    for line in saved.lines() {
        if let Some((path, val)) = line.split_once('=') {
            if FORWARD_SYSCTLS.contains(&path) && matches!(val, "0" | "1") {
                if let Err(e) = std::fs::write(path, val) {
                    failure = Some(anyhow::Error::new(e).context(format!("restore {path}")));
                }
            }
        }
    }
    match failure {
        None => {
            let _ = std::fs::remove_file(SYSCTL_STATE);
            Ok(())
        }
        Some(e) => Err(e),
    }
}

const TABLE_NAME: &str = "fishnet";

fn iface_bytes(name: &str) -> Vec<u8> {
    let mut b = name.as_bytes().to_vec();
    b.push(0);
    b
}

/// Setup firewall/NAT rules. 
/// - forward chain (Firewall): decides which package the host is willling to relay between
///   interfaces. `Drop`: nothing gets forwarded. Only two excelptions: 1. `out_rule`: traffic to
///   uplink is allowed (outbound traffic), 2. `in_rule`: traffic from the uplink is allowed only if
///   its a reply to somthing fishnetns has already sent. 
/// - postrouting chain (NAT): handles address translation, policy `Accept`
///
/// **Masquerade** map internal ip to hosts own real IP. Masquerade rewrites the source address to
/// the host's own real IP as packets exit via the uplink and un-rewrites replies on the way back in.
pub fn setup_nat_and_forward(
    veth_host: &str,
    uplink: &str,
    subnet4: Ipv4Addr,
    prefix4: u8,
    subnet6: Ipv6Addr,
    prefix6: u8,
) -> Result<()> {
    let mut batch = Batch::new();

    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
    batch.add(&table, MsgType::Add);

    let mut forward = Chain::new(&table)
        .with_name("forward")
        .with_type(ChainType::Filter)
        .with_hook(Hook::new(HookClass::Forward, 0));
    forward.set_policy(ChainPolicy::Drop);
    batch.add(&forward, MsgType::Add);

    // fishnetns -> uplink: allowed unconditionally. Interface-name matching,
    // not protocol-specific, so this single rule covers both v4 and v6.
    let out_rule = Rule::new(&forward)?
        .with_expr(Meta::new(MetaType::IifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(veth_host)))
        .with_expr(Meta::new(MetaType::OifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(uplink)))
        .with_expr(Immediate::new_verdict(VerdictKind::Accept));
    batch.add(&out_rule, MsgType::Add);

    // uplink -> fishnetns: only established/related reply traffic. Also
    // protocol-agnostic — conntrack state doesn't care about v4 vs v6.
    let state_mask = (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED)
        .bits()
        .to_le_bytes();
    let in_rule = Rule::new(&forward)?
        .with_expr(Meta::new(MetaType::IifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(uplink)))
        .with_expr(Meta::new(MetaType::OifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(veth_host)))
        .with_expr(Conntrack::new(ConntrackKey::State))
        .with_expr(Bitwise::new(state_mask.to_vec(), [0u8; 4].to_vec())?)
        .with_expr(Cmp::new(CmpOp::Neq, [0u8; 4]))
        .with_expr(Immediate::new_verdict(VerdictKind::Accept));
    batch.add(&in_rule, MsgType::Add);

    let mut postrouting = Chain::new(&table)
        .with_name("postrouting")
        .with_type(ChainType::Nat)
        .with_hook(Hook::new(HookClass::PostRouting, 100));
    postrouting.set_policy(ChainPolicy::Accept);
    batch.add(&postrouting, MsgType::Add);

    // IPv4 masquerade, scoped to the namespace's own subnet.
    let mask4: u32 = if prefix4 == 0 { 0 } else { !0u32 << (32 - prefix4) };
    let network4 = u32::from(subnet4) & mask4;
    let masq4 = Rule::new(&postrouting)?
        .with_expr(Meta::new(MetaType::NfProto))
        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV4 as u8]))
        .with_expr(
            rustables::expr::HighLevelPayload::Network(rustables::expr::NetworkHeaderField::IPv4(
                rustables::expr::IPv4HeaderField::Saddr,
            ))
            .build(),
        )
        .with_expr(Bitwise::new(mask4.to_be_bytes().to_vec(), [0u8; 4].to_vec())?)
        .with_expr(Cmp::new(CmpOp::Eq, network4.to_be_bytes()))
        .with_expr(Meta::new(MetaType::OifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(uplink)))
        .with_expr(Masquerade::default());
    batch.add(&masq4, MsgType::Add);

    // IPv6 masquerade (NAT66), scoped to the namespace's ULA subnet, letting IPv6 traffic bypass
    // the VPN/NAT entirely whenever it had any path at all.
    let mask6: u128 = if prefix6 == 0 { 0 } else { !0u128 << (128 - prefix6) };
    let network6 = u128::from(subnet6) & mask6;
    let masq6 = Rule::new(&postrouting)?
        .with_expr(Meta::new(MetaType::NfProto))
        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
        .with_expr(
            rustables::expr::HighLevelPayload::Network(rustables::expr::NetworkHeaderField::IPv6(
                rustables::expr::IPv6HeaderField::Saddr,
            ))
            .build(),
        )
        .with_expr(Bitwise::new(mask6.to_be_bytes().to_vec(), [0u8; 16].to_vec())?)
        .with_expr(Cmp::new(CmpOp::Eq, network6.to_be_bytes()))
        .with_expr(Meta::new(MetaType::OifName))
        .with_expr(Cmp::new(CmpOp::Eq, iface_bytes(uplink)))
        .with_expr(Masquerade::default());
    batch.add(&masq6, MsgType::Add);

    batch.send().context("apply nftables rules via netlink")?;
    Ok(())
}

/// Idempotent teardown, called from `down`: removes the nft table and restores the sysctls.
pub fn teardown() -> Result<()> {
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    let _ = batch.send();

    if let Err(e) = restore_ip_forward() {
        eprintln!("warning: couldn't restore ip forwarding sysctls: {e:#}");
    }
    Ok(())
}
