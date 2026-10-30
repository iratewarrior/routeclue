# RouteClue: Positioning & Scope

RouteClue is a practical, personal macOS utility that keeps split-tunneling sane. It combines an isolated packet-filter kill switch that does not depend on VPN server addresses, self-healing routes for private corporate subnets with `-ifscope`, per-zone split DNS in `/etc/resolver`, and diagnostic tooling (doctor, path explainer, declarative policy verification, and drift diffing).

## Role and Philosophy

1. **Practical Personal Tool**: RouteClue is designed to solve real everyday macOS split-tunneling failures (dropped tunnels leaking traffic, route table drift after network changes, DNS resolution conflicts) without running background daemons or kernel extensions.
2. **Explain, Heal, and Protect**:
   - **Explain**: Walk the full chain (DNS resolver → routing entry → interface IP → firewall policy) for any destination.
   - **Heal**: Re-create scoped routes and `/etc/resolver` files atomically when networks transition.
   - **Protect**: Enforce leak protection inside an isolated PF anchor (`com.apple/routeclue`) without touching global system rules.
3. **Honest Scope**:
   - No background services or long-running daemons.
   - No telemetry, analytics, or external phone-home.
   - No artificial market gates or framework overhead.
   - Honest dependencies: `RouteClueCore` is built purely on Apple's Swift standard library and Foundation; the CLI utilizes `swift-argument-parser`.

## Limitations & Non-Goals

- **Not a VPN**: RouteClue does not terminate tunnels or implement cryptographic protocols (WireGuard, OpenVPN, IPsec). It configures system routing and packet filtering around tunnels managed by external software.
- **No Background Daemon**: Execution is strictly on-demand (CLI subcommands or Menu Bar UI popover).
- **IPv4-Focused Routing**: Route healing and path explainer focus on IPv4 subnets and gateway reachability. IPv6 traffic on physical interfaces is blocked by the kill switch (except ICMPv6 ND and root processes), but RouteClue does not configure IPv6 routes.
- **Root Bypass**: Processes running as UID 0 bypass the kill switch so VPN daemons can maintain connectivity regardless of server rotation.
- **Existing Connection States**: Packet filter states established prior to enabling the kill switch persist until natural timeout.
- **PF Runtime Enforcement**: Firewall rules are validated syntactically and applied into kernel anchors under strict lockfiles, but runtime packet dropping is enforced by the Darwin kernel PF subsystem.
