# Positioning: explain and verify, do not control

## What already exists

| Tool | Category | Covers |
|---|---|---|
| [RiftRoute](https://github.com/Amirhat/riftroute) | routing controller (Go, daemon + GUI + CLI) | profiles, route reconciliation with watchdog, kill switch, split DNS, leak/drift diagnostics |
| [splitroute](https://github.com/matantczak/splitroute) | host-route helper (Bash) | per-host routes via a second interface, `/etc/resolver` files |
| pf kill-switch scripts | snippets | block egress when a tunnel is down |
| LuLu, client firewalls | app firewall | per-application allow/deny |
| VPN clients (Happ, Clash, WireGuard, …) | tunnel + their own kill switch | traffic, sometimes routing rules |

Building another controller would duplicate RiftRoute, and it would do it worse: its apply protocol,
watchdog and auto-revert are the result of real incidents.

## The gap

None of these answers the question users actually ask: **"why exactly does this host not work?"**
The answer lives in four independent layers, and each tool sees only one of them:

1. **DNS** — a scoped resolver in `/etc/resolver` may answer, the global resolver may not, and
   `dig`/`nslookup` ignore scoped resolvers entirely (they read `/etc/resolv.conf`). A public
   resolver returning `NXDOMAIN` says nothing about the private zone.
2. **Route** — the default route may be in the tunnel while the private subnet route points at the
   gateway of a network you left an hour ago.
3. **Source address** — the route can be correct and the packet still dropped, because macOS picks
   the source address of the primary interface (the tunnel) for a route that leaves via the LAN.
4. **Policy** — the kill switch may be dropping the packet, or the tunnel's own DNS interception may
   answer port 53 while the corporate server never sees the query. "Port 53 is open" proves nothing.

Observed in practice, repeatedly: correct rules, correct routes, and still "the site does not open" —
because one layer contradicts another.

## Thesis

**TunnelGuard explains and verifies; it does not route.** It reads the system state, never owns it,
and never runs a daemon. That makes it complementary to any tunnel client and to RiftRoute itself:

- point it at a hostname and get the full chain with evidence;
- declare what must be true ("this name resolves internally", "this subnet bypasses the tunnel",
  "with the tunnel down nothing leaks") and get pass/fail with the reason;
- snapshot the state, change networks, diff — drift becomes visible instead of mysterious.

## What makes it different

| | RiftRoute | splitroute | kill-switch scripts | TunnelGuard |
|---|---|---|---|---|
| Explains DNS → route → source → policy for a host | routes only | no | no | **yes** |
| Detects source-address mismatch (`-ifscope`) | partially (route checks) | no | no | **yes** |
| Detects resolver contradiction (scoped vs global vs raw) | no | no | no | **yes** |
| Real DNS query instead of a port check | partial | no | no | **yes** |
| Verifies a declared policy (pass/fail, CI-friendly) | drift for routes | no | no | **planned** |
| Owns/manages routes | yes | yes | no | no (only proposes) |
| Daemon | yes | no | no | **no** |
| Dependencies | Go, SQLite, Wails | bash | bash | **none** |
| Telemetry | optional, on by default | no | no | **never** |

## Scope

v0.1 (implemented): `explain <host>`, `doctor`, kill switch, route healing, split-DNS management.
v0.2: `verify` with a declarative policy file and exit codes for CI; `snapshot`/`diff`.
v0.3: menu bar surfaces `explain` for a host from the clipboard; JSON output.

Explicit non-goals: being a VPN, running tunnels, owning the routing table, background services,
per-app rule engines.

## Success criterion

A user with a broken corporate resource runs one command and learns **which layer** is wrong —
without reading ten forum threads about `scutil --dns`, `-ifscope` and pf ordering.
