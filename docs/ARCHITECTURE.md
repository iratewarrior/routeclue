# Architecture

TunnelGuard is a thin shell around four system facilities. There is no network extension, no
privileged daemon and no background service: every action is a command that runs when you ask.

```
TunnelGuardApp (SwiftUI, menu bar)      tunnelguard (CLI)
                 \                      /
                  \                    /
                 TunnelGuardCore (library)
                   ├── RouteManager   routes, gateways, -ifscope
                   ├── KillSwitch     pf ruleset generation and validation
                   ├── DNSZones       /etc/resolver files
                   ├── DNSQuery       minimal UDP DNS client for probes
                   ├── Diagnostics    aggregated state
                   ├── Config         JSON in Application Support
                   └── Shell          Process wrapper + privileged execution
```

## Privilege model

Read operations (`route get`, `netstat`, `scutil`, `ifconfig`) run as the current user.
Write operations (routes, `pfctl`, `/etc/resolver`) go through `Shell.privileged(_:)`:

1. if the process is already root — run `/bin/sh -c` directly;
2. otherwise — `osascript -e 'do shell script "..." with administrator privileges'`, which shows
   the standard macOS authorization dialog.

There is no stored credential and no helper that keeps root after the action finishes.

## Kill switch ruleset

Generated from configuration on every `on`, written to `/tmp/tunnelguard-pf.conf`, parsed with
`pfctl -n` (dry run) and only then applied with `pfctl -f` + `pfctl -E`.

Order matters: `pass` rules come first and are `quick`, so the final `block drop out quick ... all`
only sees traffic that matched nothing above. System anchors from `/etc/pf.conf` are copied verbatim,
otherwise loading a custom ruleset would disable the macOS application firewall.

The allow rule is based on the socket owner (`user = 0`) instead of the VPN server address, because
providers rotate servers and subnets. See `docs/SECURITY.md` for consequences.

## Route healing

`RouteManager.ensure` reads the LAN gateway from `ipconfig getoption <iface> router`, then for each
configured subnet:

```
route delete -net <subnet>                 # drop stale entry, ignore errors
route add -net <subnet> <gw> -ifscope <if> # pin source address to the LAN interface
```

`-ifscope` is the important part: without it macOS may pick the source address of the primary
interface (the tunnel) and the corporate network silently drops such packets.

## Split DNS

For each enabled zone a file is written to `/etc/resolver/<zone>`:

```
nameserver 10.0.0.10
nameserver 10.0.0.11
search_order 1
timeout 2
```

mDNSResponder consults these before the global resolvers. `dig` and `nslookup` do not, which is why
diagnostics use `dscacheutil`-level checks and a raw DNS client instead.

## Diagnostics

`DNSQuery` builds a single A-record query, sends it over UDP with a timeout and parses the answer,
including compressed names. This distinguishes "server is down" from "port is open because something
intercepts DNS" — a difference that plain port checks cannot see.
