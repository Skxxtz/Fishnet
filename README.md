# fishnet

Run selected apps through a VPN on Linux, without touching the rest of your system.

fishnet creates a network namespace (`fishnetns`), connects it to the internet through a veth pair with NAT, and lets you bring up a WireGuard VPN *inside* it. Apps started with `fishnet exec` only run once the VPN is up (kill switch), and only they use the tunnel. Everything else on the host keeps its normal route.

## Requirements

- Linux with network namespaces, nftables and WireGuard support (any distro)
- Root (use `sudo`; `exec` drops back to the invoking user via `SUDO_UID`/`SUDO_GID`)
- A WireGuard client, e.g. `wg-quick` (the interface **must be named `wg*`**, e.g. `wg0`)
- `curl` (only used by `status` for a reachability check)

## Quick start

```sh
sudo fishnet up                                  # create namespace + NAT
sudo fishnet connect -- wg-quick up ./wg0.conf   # bring the VPN up inside it (as root)
sudo fishnet exec -- curl ifconfig.me            # run as YOU, through the VPN
sudo fishnet exec -d -- firefox                  # detached, for GUI apps
sudo fishnet status
sudo fishnet ps
sudo fishnet down                                # kill everything, remove all state
```

## Commands

| Command | What it does |
|---|---|
| `up` | Create `fishnetns`, veth pair, forwarding + nftables NAT. Rebuilds cleanly if stale state exists. |
| `connect -- <cmd>` | Run `<cmd>` as **root** inside the namespace, **without** the kill switch. Meant only for your VPN client's connect command. |
| `exec [-d] -- <cmd>` | Run `<cmd>` as the invoking user inside the namespace. Refuses to run unless a `wg*` interface exists. `-d` detaches (double-fork, `setsid`, null stdio). |
| `status` | Shows namespace, veth, uplink, VPN state, process count and your exit IP. |
| `ps [-f]` | Lists processes inside the namespace. `-f` disables truncation. |
| `down` | Kills all processes in the namespace, removes nft rules, veth and namespace, restores sysctls. Idempotent. |

## How it works

```
 host                                   fishnetns
┌───────────────────────┐             ┌──────────────────────────┐
│ vh0  10.200.1.1/24    │◄── veth ───►│ vn0  10.200.1.2/24       │
│      fd00:fefe:cafe::1│             │      fd00:fefe:cafe::2   │
│                       │             │ wg0  (your VPN)          │
│ nftables: forward     │             │ default route → vh0,     │
│ drop + masquerade     │             │ then taken over by wg0   │
└──────────┬────────────┘             └──────────────────────────┘
           │ auto-detected uplink (default v4 route)
         internet
```

- **Uplink** is auto-detected from the default IPv4 route (no hardcoded `eth0`/`wlan0`).
- **Firewall**: nft table `inet fishnet`. The forward chain drops by default; only `vh0 → uplink` and established/related replies back are allowed. Masquerade (IPv4 and IPv6/NAT66) is scoped to the namespace subnets.
- **IP forwarding** sysctls (v4 + v6) are enabled on `up`; original values are saved in `/run/fishnet` and restored on `down`.
- **DNS**: `/etc/netns/fishnetns/resolv.conf` (seeded from the host's) is bind-mounted over `/etc/resolv.conf` in a private mount namespace per command, so a VPN client's `resolvconf` never touches the host's DNS.
- **Process discovery** matches `/proc/<pid>/ns/net` against the namespace file, so it catches detached and double-forked processes and needs no cgroups or systemd.

## Security notes

`exec` runs commands with the caller's identity and hardening: environment allowlist (no `LD_PRELOAD` etc.), sanitized `PATH`, empty capability bounding set, supplementary groups from the caller, `no_new_privs`, and a check that root can't be regained. `connect` stays root but only trusts root-owned, non-world-writable `PATH` entries. Never pass untrusted commands to `connect`.

**Limitations**
- The kill switch is checked when a command *starts*. If the VPN interface disappears later, already-running apps fall back to the plain NAT route. Prefer stopping them (`fishnet down`) if the tunnel drops.
- Only interfaces named `wg*` count as "VPN connected". Other VPN types aren't detected.
- The check looks for the interface, not for a working tunnel or correct routes. Verify with `fishnet status`.

## Install

### NixOS (flake)

```nix
{
  inputs.fishnet.url = "github:<you>/fishnet";

  outputs = { nixpkgs, fishnet, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        fishnet.nixosModules.default
        {
          programs.fishnet = {
            enable = true;
            sudoGroup = "fishnet"; # optional
          };
          users.users.me.extraGroups = [ "fishnet" ];
        }
      ];
    };
  };
}
```

With `sudoGroup` set, members may run `fishnet up|down|status|ps|exec` via sudo without a password. `connect` always requires one.

### Other distros

Install build dependencies, then build with Cargo (Rust 1.85+, edition 2024):

| Dependency | Debian/Ubuntu | Fedora | Arch |
|---|---|---|---|
| libnftnl | `libnftnl-dev` | `libnftnl-devel` | `libnftnl` |
| libmnl | `libmnl-dev` | `libmnl-devel` | `libmnl` |
| clang (bindgen) | `libclang-dev` | `clang-devel` | `clang` |
| pkg-config | `pkg-config` | `pkgconf` | `pkgconf` |
| kernel headers | `linux-libc-dev` | `kernel-headers` | `linux-api-headers` |

```sh
cargo build --release
sudo install -m755 target/release/fishnet /usr/local/bin/
```

## Development

```sh
nix develop      # dev shell with all native deps
cargo build
nix build        # reproducible package
```

Tests would need root and real namespaces, so they are disabled in the Nix build.
