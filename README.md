# TunnelGuard

A small macOS utility that keeps split tunnelling sane: a kill switch that does not depend on the
VPN server address, self-healing routes for private subnets, and split DNS for internal zones.

Menu bar app + CLI, no daemon, no telemetry, MIT licensed.

```
$ tunnelguard doctor
LAN: en0 192.168.1.104 → 192.168.1.1
Tunnel: utun3 (up), default: utun3
System resolvers: 1.1.1.1, 10.0.0.10
Route 10.20.0.0/16: 192.168.1.1 via en0 [ok]
Zone corp.example.com: DNS answers, intranet.corp.example.com → 10.20.5.11
Exit address: 203.0.113.42
```

## Why

Split tunnelling breaks in predictable ways, and every VPN client handles them differently:

| Problem | What usually happens | What TunnelGuard does |
|---|---|---|
| Tunnel drops for a second | traffic silently leaves through the physical interface | pf rules allow only the tunnel core, LAN, and explicit destinations; everything else is dropped |
| VPN provider rotates servers | kill switch pinned to an IP stops working or blocks the tunnel | rules are bound to the tunnel core's uid, not to an address |
| Corporate subnets unreachable while the tunnel is up | route points into the tunnel, or worse, into the previous network's gateway | recreates routes through the current LAN gateway with `-ifscope` |
| Packets leave with the tunnel's source address | corporate network drops them silently | `-ifscope` pins the source address to the LAN interface |
| Internal names do not resolve | the VPN client replaces system DNS | writes scoped resolvers to `/etc/resolver` |
| "Port 53 is open" but DNS is dead | port checks lie when DNS is intercepted | sends a real DNS query and parses the answer |

## Features

- **Kill switch** — pf ruleset with system anchors preserved; validates the ruleset before applying.
- **Route healing** — `tunnelguard routes ensure` recreates routes to your subnets via the current gateway.
- **Split DNS** — per-zone resolvers in `/etc/resolver`, applied and removed from one place.
- **Diagnostics** — gateway, default interface, tunnel state, real DNS probes, exit address.
- **Two front ends** — `tunnelguard` CLI and a menu bar app sharing the same core.
- **No dependencies** — Swift standard library only.

## Requirements

- macOS 13 or newer.
- Swift 5.9+ toolchain (Command Line Tools are enough to build).
- Administrator rights for routes, pf and `/etc/resolver` — the app asks through the standard
  macOS authorization dialog.

## Build

```bash
git clone https://github.com/<you>/tunnelguard.git
cd tunnelguard

swift build -c release     # CLI: .build/release/tunnelguard
swift run TunnelGuardSelfTest  # 22 self checks, no test framework needed

./Scripts/build-app.sh     # produces TunnelGuard.app in ./dist
./Scripts/install-cli.sh   # optional: copies the CLI to /usr/local/bin
```

## Configure

Configuration lives in `~/Library/Application Support/TunnelGuard/config.json`.
Everything can be set from the CLI, no hand-editing required.

```bash
# subnets that must bypass the tunnel
tunnelguard config add-subnet 10.20.0.0/16

# private zone → internal resolvers
tunnelguard config add-zone corp.example.com 10.0.0.10 10.0.0.11

# host used to verify that zone resolution actually works
tunnelguard config set-probe intranet.corp.example.com

# DNS servers reachable directly on port 53 (optional)
tunnelguard config set-dns 10.0.0.10
```

Resulting config:

```json
{
  "corpSubnets": ["10.20.0.0/16"],
  "lanInterfaces": ["en0"],
  "tunnelPrefix": "utun",
  "dnsZones": [
    { "zone": "corp.example.com", "nameservers": ["10.0.0.10", "10.0.0.11"], "enabled": true }
  ],
  "killSwitch": {
    "allowNets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"],
    "allowListPath": null,
    "extraAllow": [],
    "dnsAllow": []
  },
  "probeHosts": ["intranet.corp.example.com"]
}
```

## Use

```bash
tunnelguard explain <host>       # DNS → route → source address → policy verdict
tunnelguard status              # one screen: LAN, tunnel, routes, exit address
tunnelguard doctor              # full diagnostics
tunnelguard routes ensure        # recreate routes with -ifscope
tunnelguard killswitch on        # enable leak protection
tunnelguard killswitch off       # restore macOS rules
tunnelguard dns apply            # write /etc/resolver files
```

The menu bar app exposes the same actions. Its diagnostics window shows the same report as `doctor`.

## Why explain instead of just configure

Split tunnelling fails in layers: a scoped resolver may answer while the global one does not, a route
may point at a gateway you left an hour ago, a correct route can still send packets with the tunnel's
source address, and a kill switch may drop what you expect to work. `tunnelguard explain` walks the
whole chain and reports the contradiction instead of a guess. See
[docs/POSITIONING.md](docs/POSITIONING.md) for how this compares to existing tools.

## How the kill switch works

```
pass out quick on en0 inet user = 0 keep state        # tunnel core (root) — any server address
pass out quick on en0 inet to { 10.0.0.0/8, ... }      # LAN and private ranges
pass out quick on en0 inet to <allowlist>              # optional extra prefixes
pass out quick on en0 inet proto { tcp, udp } to { ... } port 53
block drop out quick on en0 inet all                   # nothing else leaves directly
```

Tunnel clients run their core as root, so the encrypted stream is always allowed while ordinary
processes can only reach the destinations listed above. If the tunnel dies, application traffic has
nowhere to go — which is the point.

## Limitations

- This is not a VPN. It manages routing and firewall rules around a tunnel you already run.
- A root process can still reach the network directly; the rule is an allow for uid 0.
- `dig` and `nslookup` ignore `/etc/resolver`; verify resolution with `dscacheutil` or an app.
- Rules are evaluated per interface (`en*`); exotic setups (bridged interfaces, VM adapters) may
  need `allowNets` adjustments.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for module layout.

## Roadmap

- LaunchAgent that re-applies routes after network changes (opt-in).
- Import/export of profiles (office / home / travel).
- IPv6-aware route management.
- `--json` output for diagnostics.

## License

MIT — see [LICENSE](LICENSE).
