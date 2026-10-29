# Security notes

## What TunnelGuard protects

- **Leak on tunnel failure.** If the tun interface disappears, the default route returns to the
  physical interface. The generated pf ruleset allows only the tunnel core, private ranges, the
  optional allow-list and explicitly configured DNS servers; every other outbound packet on `en*` is
  dropped.
- **Stale routes after switching networks.** Routes are recreated against the gateway that is
  actually in use, with `-ifscope`.
- **Wrong source address.** `-ifscope` prevents packets from leaving with the tunnel's address,
  which corporate networks drop.
- **Private name resolution.** Scoped resolvers in `/etc/resolver` keep internal zones on internal
  DNS instead of leaking queries to a public resolver.

## What it does not protect

- **It is not a VPN.** No encryption and no transport. It shapes routes and firewall rules around a
  tunnel you already run.
- **Root processes are trusted.** The allow rule is `user = 0`; anything running as root can still
  reach the network directly. This is the price of not depending on a server address.
- **A hostile kernel or a compromised tunnel client** is out of scope.
- **Corporate policy.** Using a personal tunnel alongside a corporate network may violate policy.
  This tool does not change that.

## Privileges

Privileged commands are executed through the macOS authorization dialog (`osascript … with
administrator privileges`). Nothing is stored, no root helper stays resident, and no LaunchDaemon is
installed. The ruleset is validated with `pfctl -n` before it is loaded, so a malformed rule cannot
lock the machine out of the network silently.

Restoring the system state is one command:

```bash
tunnelguard killswitch off     # pfctl -f /etc/pf.conf; pfctl -d
```

## Files touched

| Path | Purpose |
|---|---|
| `/tmp/tunnelguard-pf.conf` | generated ruleset (recreated on every enable) |
| `/etc/resolver/<zone>` | split-DNS files, removed when a zone is disabled |
| `~/Library/Application Support/TunnelGuard/config.json` | configuration |
| routing table | `-ifscope` routes for configured subnets |
| pf | ruleset replaced while the kill switch is on |

## Reporting

Open an issue with the output of `tunnelguard doctor` (it contains no credentials) and the exact
macOS version.
