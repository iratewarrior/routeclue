import Foundation
import TunnelGuardCore

func printHelp() {
    print("""
    tunnelguard — routing and leak protection for macOS

    USAGE
      tunnelguard status                     short state
      tunnelguard explain <host>             explain DNS, route, source address and verdict
      tunnelguard doctor                     full diagnostics
      tunnelguard routes list|ensure|remove
      tunnelguard killswitch on|off|status
      tunnelguard dns list|apply|remove <zone>
      tunnelguard config path|show|init
      tunnelguard config add-subnet <cidr>   e.g. 10.0.0.0/8
      tunnelguard config add-zone <zone> <ns> [ns...]
      tunnelguard config set-probe <host>    host used to verify zone resolution
      tunnelguard config set-dns <server>    DNS allowed directly on port 53
      tunnelguard config set-iface <name>    LAN interface, e.g. en0

    CONFIG
      \(ConfigStore.fileURL.path)

    Privileged operations (routes, kill switch, /etc/resolver) ask for a password
    through the standard macOS authorization dialog.
    """)
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    printHelp()
    exit(0)
}

var config = ConfigStore.load()

switch command {
case "status":
    let report = Diagnostics.snapshot(config: config)
    print("LAN: \(report.lanAddress ?? "—") → \(report.gateway ?? "—")")
    print("Tunnel: \(report.tunnelUp ? "up" : "down"), default: \(report.defaultInterface ?? "—")")
    if let state = KillSwitch.isEnabled() {
        print("Kill switch: \(state ? "on" : "off")")
    } else {
        print("Kill switch: unknown (run with sudo to read pf state)")
    }
    for route in report.routes {
        print("Route \(route.subnet): \(route.gateway ?? "—")\(route.ifScoped ? " [ifscope]" : "")")
    }
    print("Exit address: \(report.exitIP ?? "—")")

case "doctor":
    print(Diagnostics.snapshot(config: config).summary)

case "routes":
    switch args.count > 1 ? args[1] : "list" {
    case "list":
        let routes = RouteManager.status(config)
        if routes.isEmpty { print("No subnets configured.") }
        for route in routes {
            let scope = route.ifScoped ? "ifscope" : "no ifscope"
            print("\(route.subnet)\t\(route.gateway ?? "missing")\t\(route.interface ?? "—")\t\(scope)")
        }
    case "ensure":
        for line in try RouteManager.ensure(config) { print(line) }
    case "remove":
        for line in try RouteManager.remove(config) { print(line) }
    default:
        fail("Unknown action: \(args[1])")
    }

case "killswitch":
    switch args.count > 1 ? args[1] : "status" {
    case "on":
        let plan = try KillSwitch.apply(config)
        print("Kill switch enabled on: \(plan.interfaces.joined(separator: ", "))")
        for warning in plan.warnings { print("· \(warning)") }
    case "off":
        print(try KillSwitch.disable())
    case "status":
        switch KillSwitch.isEnabled() {
        case .some(true): print("on")
        case .some(false): print("off")
        case .none: print("unknown (run with sudo)")
        }
    default:
        fail("Unknown action: \(args[1])")
    }

case "dns":
    switch args.count > 1 ? args[1] : "list" {
    case "list":
        let installed = DNSZones.installedZones()
        print(installed.isEmpty ? "Empty \(DNSZones.directory)." : installed.joined(separator: "\n"))
        for zone in config.dnsZones {
            print("config: \(zone.zone) → \(zone.nameservers.joined(separator: ", ")) [\(zone.enabled ? "on" : "off")]")
        }
    case "apply":
        print(try DNSZones.apply(config.dnsZones))
    case "remove":
        guard args.count > 2 else { fail("Usage: tunnelguard dns remove <zone>") }
        print(try DNSZones.remove(zone: args[2]))
    default:
        fail("Unknown action: \(args[1])")
    }

case "explain":
    guard args.count > 1 else { fail("Usage: tunnelguard explain <host>") }
    print(PathExplainer.explain(host: args[1], config: config).summary)

case "config":
    let action = args.count > 1 ? args[1] : "path"
    switch action {
    case "path":
        print(ConfigStore.fileURL.path)
    case "show":
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(config), as: UTF8.self))
    case "init":
        try ConfigStore.save(config)
        print("Config written to \(ConfigStore.fileURL.path)")
    case "add-subnet":
        guard args.count > 2 else { fail("Usage: tunnelguard config add-subnet 10.0.0.0/8") }
        if !config.corpSubnets.contains(args[2]) { config.corpSubnets.append(args[2]) }
        try ConfigStore.save(config)
        print("Subnets: \(config.corpSubnets.joined(separator: ", "))")
    case "add-zone":
        guard args.count > 3 else { fail("Usage: tunnelguard config add-zone corp.example.com 10.0.0.10 [10.0.0.11]") }
        let zone = DNSZone(zone: args[2], nameservers: Array(args[3...]))
        config.dnsZones.removeAll { $0.zone == zone.zone }
        config.dnsZones.append(zone)
        try ConfigStore.save(config)
        print("Zone \(zone.zone) → \(zone.nameservers.joined(separator: ", "))")
    case "set-probe":
        guard args.count > 2 else { fail("Usage: tunnelguard config set-probe intranet.example.com") }
        config.probeHosts = [args[2]]
        try ConfigStore.save(config)
        print("Probe host: \(args[2])")
    case "set-dns":
        guard args.count > 2 else { fail("Usage: tunnelguard config set-dns 1.1.1.1") }
        if !config.killSwitch.dnsAllow.contains(args[2]) { config.killSwitch.dnsAllow.append(args[2]) }
        try ConfigStore.save(config)
        print("Allowed DNS: \(config.killSwitch.dnsAllow.joined(separator: ", "))")
    case "set-iface":
        guard args.count > 2 else { fail("Usage: tunnelguard config set-iface en0") }
        config.lanInterfaces = [args[2]]
        try ConfigStore.save(config)
        print("LAN interface: \(args[2])")
    default:
        fail("Unknown action: \(action)")
    }

case "--help", "-h", "help":
    printHelp()

default:
    fail("Unknown command: \(command). Try tunnelguard --help")
}
