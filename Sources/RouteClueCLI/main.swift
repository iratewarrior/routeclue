import Foundation
import ArgumentParser
import RouteClueCore

@main
struct RouteClueCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "routeclue",
        abstract: "Split-tunneling diagnostics, self-healing routes and leak protection for macOS.",
        version: "0.2.0",
        subcommands: [
            StatusCommand.self,
            DoctorCommand.self,
            ExplainCommand.self,
            RoutesCommand.self,
            KillSwitchCommand.self,
            DNSCommand.self,
            SnapshotCommand.self,
            DiffCommand.self,
            VerifyCommand.self,
            ConfigCommand.self,
            SetupCommand.self,
        ],
        defaultSubcommand: StatusCommand.self
    )
}

// MARK: - Status & Doctor

struct StatusCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "status", abstract: "Show short network state")

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let report = Diagnostics.snapshot(config: config)
        let ksState = KillSwitch.isEnabled()

        if json {
            let snap = NetworkSnapshot(report: report, killSwitchActive: ksState)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(snap), as: UTF8.self))
            return
        }

        print("LAN: \(report.lanAddress ?? "—") → \(report.gateway ?? "—")")
        print("Tunnel: \(report.tunnelUp ? "up" : "down"), default: \(report.defaultInterface ?? "—")")
        if let state = ksState {
            print("Kill switch: \(state ? "on" : "off")")
        } else {
            print("Kill switch: unknown (run with sudo to read pf state)")
        }
        for route in report.routes {
            print("Route \(route.subnet): \(route.gateway ?? "—")\(route.ifScoped ? " [ifscope]" : "")")
        }
        print("Exit address: \(report.exitIP ?? "—")")
    }
}

struct DoctorCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "doctor", abstract: "Run full network diagnostics")

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let report = Diagnostics.snapshot(config: config)
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(report), as: UTF8.self))
        } else {
            print(report.summary)
        }
    }
}

// MARK: - Explain

struct ExplainCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "explain", abstract: "Explain DNS, route, source address and firewall verdict for a host")

    @Argument(help: "Hostname or URL to inspect")
    var host: String

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let cleanHost: String
        switch TargetInputNormalizer.normalize(host) {
        case let .success(normalized):
            cleanHost = normalized
        case let .failure(error):
            print("Error: \(error.localizedDescription)")
            throw ExitCode(1)
        }

        let config = try ConfigStore.load()
        let explanation = PathExplainer.explain(host: cleanHost, config: config)

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(explanation), as: UTF8.self))
            return
        }

        // Красивое форматированное дерево слоев в терминале
        let isTTY = isatty(STDOUT_FILENO) != 0
        let bold = isTTY ? "\u{001B}[1m" : ""
        let green = isTTY ? "\u{001B}[32m" : ""
        let red = isTTY ? "\u{001B}[31m" : ""
        let yellow = isTTY ? "\u{001B}[33m" : ""
        let cyan = isTTY ? "\u{001B}[36m" : ""
        let reset = isTTY ? "\u{001B}[0m" : ""

        print("\(bold)🔍 RouteClue Path Explainer: \(cyan)\(cleanHost)\(reset)\n")

        // Layer 1: DNS
        let dnsPass = explanation.dnsError == nil && !explanation.addresses.isEmpty
        let dnsColor = dnsPass ? green : red
        let dnsSym = dnsPass ? "✔ PASS" : "✖ FAIL"
        let resolver = explanation.resolverDomain.map { "scoped zone \($0)" } ?? "global resolver"
        print("  \(bold)Layer 1: DNS Resolution\(reset)           \(dnsColor)\(dnsSym)\(reset)")
        print("  ├─ Resolver:    \(resolver) → \(explanation.resolverServers.joined(separator: ", "))")
        if let err = explanation.dnsError {
            print("  └─ Error:       \(red)\(err)\(reset)")
        } else {
            print("  └─ Result:      \(explanation.addresses.joined(separator: ", "))")
        }
        print("")

        // Layer 2 & 3: Route & Source
        for (idx, path) in explanation.paths.enumerated() {
            let isLast = idx == explanation.paths.count - 1
            let prefixChar = isLast ? "└" : "├"
            let routePass = path.gateway != nil
            let rColor = routePass ? green : red
            let rSym = routePass ? "✔ PASS" : "✖ FAIL"

            print("  \(bold)Layer 2: Routing (\(path.address))\(reset)    \(rColor)\(rSym)\(reset)")
            print("  \(prefixChar)─ Interface:   \(path.interface ?? "none") → \(path.gateway ?? "no route")")

            let scopePass = path.ifScoped
            let sColor = scopePass ? green : yellow
            let sSym = scopePass ? "✔ ifscope" : "! no ifscope"
            print("  \(bold)Layer 3: Interface IP\(reset)            \(sColor)\(sSym)\(reset)")
            print("  └─ IP:          \(path.interfaceAddress ?? "—")")
            if let warn = path.warning {
                print("     \(yellow)! Warning: \(warn)\(reset)")
            }
            print("")
        }

        // Layer 4: Policy
        let ksState = explanation.killSwitchEnabled.map { $0 ? "on" : "off" } ?? "unknown"
        let ksBlocked = explanation.verdict == .blocked
        let pColor = ksBlocked ? red : green
        let pSym = ksBlocked ? "✖ BLOCKED" : "✔ ALLOWED"
        print("  \(bold)Layer 4: Kill Switch Policy\(reset)       \(pColor)\(pSym)\(reset)")
        print("  └─ Status:      killswitch is \(ksState), tunnel is \(explanation.tunnelUp ? "up" : "down")")
        print("")

        print("══════════════════════════════════════════════════════════════════════")
        let verdictColor: String
        switch explanation.verdict {
        case .direct, .viaTunnel, .loopback: verdictColor = green
        case .blocked, .dnsFailure, .noRoute: verdictColor = red
        }
        print("✨ \(bold)VERDICT:\(reset) \(verdictColor)\(explanation.verdict.rawValue.uppercased())\(reset)")
        for note in explanation.notes {
            print("  • \(note)")
        }
        print("══════════════════════════════════════════════════════════════════════")
    }
}

// MARK: - Routes

struct RoutesCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "routes",
        abstract: "Manage corporate routes bypassing the tunnel",
        subcommands: [RoutesList.self, RoutesEnsure.self, RoutesRemove.self],
        defaultSubcommand: RoutesList.self
    )
}

struct RoutesList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List configured routes and status")

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let routes = RouteManager.status(config)
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(routes), as: UTF8.self))
            return
        }
        if routes.isEmpty { print("No subnets configured.") }
        for route in routes {
            let scope = route.ifScoped ? "ifscope" : "no ifscope"
            print("\(route.subnet)\t\(route.gateway ?? "missing")\t\(route.interface ?? "—")\t\(scope)")
        }
    }
}

struct RoutesEnsure: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ensure", abstract: "Recreate routes with -ifscope via current LAN gateway")

    func run() throws {
        let config = try ConfigStore.load()
        for line in try RouteManager.ensure(config) { print(line) }
    }
}

struct RoutesRemove: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "remove", abstract: "Remove corporate routes")

    func run() throws {
        let config = try ConfigStore.load()
        for line in try RouteManager.remove(config) { print(line) }
    }
}

// MARK: - KillSwitch

struct KillSwitchCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "killswitch",
        abstract: "Control the packet filter kill switch",
        subcommands: [KillSwitchOn.self, KillSwitchOff.self, KillSwitchStatus.self],
        defaultSubcommand: KillSwitchStatus.self
    )
}

struct KillSwitchOn: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "on", abstract: "Enable kill switch via isolated pf anchor")

    func run() throws {
        let config = try ConfigStore.load()
        let plan = try KillSwitch.apply(config)
        print("Kill switch enabled on: \(plan.interfaces.joined(separator: ", "))")
        for warning in plan.warnings { print("· \(warning)") }
    }
}

struct KillSwitchOff: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "off", abstract: "Disable kill switch")

    func run() throws {
        print(try KillSwitch.disable())
    }
}

struct KillSwitchStatus: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "status", abstract: "Show kill switch state")

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let state = KillSwitch.isEnabled()
        if json {
            let dict = ["killSwitchEnabled": state]
            let data = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
            print(String(decoding: data, as: UTF8.self))
        } else {
            switch state {
            case .some(true): print("on")
            case .some(false): print("off")
            case .none: print("unknown (run with sudo to inspect pf)")
            }
        }
    }
}

// MARK: - DNS

struct DNSCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dns",
        abstract: "Manage split DNS in /etc/resolver",
        subcommands: [DNSList.self, DNSApply.self, DNSRemove.self, DNSFlush.self],
        defaultSubcommand: DNSList.self
    )
}

struct DNSList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List installed and configured resolver zones")

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let installed = DNSZones.installedZones()
        if json {
            let dict: [String: Any] = [
                "installedZones": installed,
                "configuredZones": config.dnsZones.map { ["zone": $0.zone, "nameservers": $0.nameservers, "enabled": $0.enabled] }
            ]
            let data = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
            print(String(decoding: data, as: UTF8.self))
            return
        }
        print(installed.isEmpty ? "Empty \(DNSZones.directory)." : "Installed in \(DNSZones.directory):\n  " + installed.joined(separator: "\n  "))
        for zone in config.dnsZones {
            print("config: \(zone.zone) → \(zone.nameservers.joined(separator: ", ")) [\(zone.enabled ? "on" : "off")]")
        }
    }
}

struct DNSApply: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "apply", abstract: "Sync /etc/resolver with configuration")

    func run() throws {
        let config = try ConfigStore.load()
        print(try DNSZones.apply(config.dnsZones))
    }
}

struct DNSRemove: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "remove", abstract: "Remove a resolver zone file")

    @Argument(help: "Zone domain name to remove")
    var zone: String

    func run() throws {
        print(try DNSZones.remove(zone: zone))
    }
}

struct DNSFlush: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "flush", abstract: "Flush mDNSResponder cache")

    func run() throws {
        try DNSZones.flush()
        print("DNS cache flushed.")
    }
}

// MARK: - Snapshot & Diff

struct SnapshotCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "snapshot", abstract: "Save a snapshot of network state to a file")

    @Argument(help: "Output JSON file path (defaults to ./network-snapshot.json)")
    var output: String?

    @Flag(name: .long, help: "Print snapshot to stdout in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let report = Diagnostics.snapshot(config: config)
        let snap = NetworkSnapshot(report: report, killSwitchActive: KillSwitch.isEnabled())
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(snap)

        if json && output == nil {
            print(String(decoding: data, as: UTF8.self))
            return
        }

        let target = output ?? "network-snapshot.json"
        let url = URL(fileURLWithPath: target)
        try data.write(to: url, options: .atomic)
        print("Snapshot saved to \(url.path)")
    }
}

struct DiffCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "diff", abstract: "Compare network state against a saved snapshot file")

    @Argument(help: "Path to baseline snapshot JSON file")
    var snapshotFile: String

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let url = URL(fileURLWithPath: snapshotFile)
        let data = try Data(contentsOf: url)
        let baseline = try JSONDecoder().decode(NetworkSnapshot.self, from: data)

        let config = try ConfigStore.load()
        let currentReport = Diagnostics.snapshot(config: config)
        let current = NetworkSnapshot(report: currentReport, killSwitchActive: KillSwitch.isEnabled())

        let diff = SnapshotDiff(before: baseline, after: current)
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(diff), as: UTF8.self))
        } else {
            print(diff.summary)
        }
    }
}

// MARK: - Verify

struct VerifyCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "verify", abstract: "Verify network state against declarative policy (exits non-zero on failure)")

    @Option(name: .long, help: "Path to custom JSON policy file (defaults to config-derived policy)")
    var policy: String?

    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false

    func run() throws {
        let config = try ConfigStore.load()
        let policyToVerify: RouteCluePolicy
        if let policyPath = policy {
            let data = try Data(contentsOf: URL(fileURLWithPath: policyPath))
            policyToVerify = try JSONDecoder().decode(RouteCluePolicy.self, from: data)
        } else {
            policyToVerify = RouteCluePolicy.from(config: config)
        }

        let report = PolicyVerifier.verify(policy: policyToVerify, config: config)

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(report), as: UTF8.self))
        } else {
            print(report.summary)
        }

        if !report.allPassed {
            throw ExitCode(1)
        }
    }
}

// MARK: - Setup

struct SetupCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "setup", abstract: "Interactive helper to autodetect network interfaces and configure RouteClue")

    @Option(name: .long, help: "Corporate subnet to add (e.g. 10.20.0.0/16)")
    var subnet: String?

    @Option(name: .long, help: "Corporate DNS zone (e.g. corp.example.com=10.0.0.10)")
    var zone: String?

    func run() throws {
        var config = try ConfigStore.load()
        print("🚀 RouteClue Automated Setup\n")

        let endpoints = RouteManager.endpoints(config)
        if let ep = endpoints.first {
            print("✔ Detected LAN interface: \(ep.interface) (IP: \(ep.address), Gateway: \(ep.gateway))")
            config.lanInterfaces = [ep.interface]
        } else {
            print("! Could not autodetect LAN gateway. Keeping: \(config.lanInterfaces.joined(separator: ", "))")
        }

        let defIface = Diagnostics.defaultRouteInterface()
        let tun = Diagnostics.tunnelInterface(prefix: config.tunnelPrefix, defaultInterface: defIface)
        if let tun {
            print("✔ Detected active VPN tunnel interface: \(tun)")
        } else {
            print("ℹ No active tunnel interface detected right now.")
        }

        if let sub = subnet {
            guard RouteManager.isValidSubnet(sub) else {
                print("✖ Invalid subnet CIDR format: \(sub)")
                throw ExitCode(1)
            }
            if !config.corpSubnets.contains(sub) {
                config.corpSubnets.append(sub)
                print("✔ Added corporate subnet: \(sub)")
            }
        }

        if let z = zone {
            let parts = z.split(separator: "=")
            if parts.count == 2 {
                let zName = String(parts[0])
                let servers = parts[1].split(separator: ",").map(String.init)
                guard DNSZones.isValidZoneName(zName) else {
                    print("✖ Invalid zone name: \(zName)")
                    throw ExitCode(1)
                }
                for ns in servers {
                    guard DNSZones.isValidNameserver(ns) else {
                        print("✖ Invalid nameserver IP: \(ns)")
                        throw ExitCode(1)
                    }
                }
                config.dnsZones.removeAll { $0.zone == zName }
                config.dnsZones.append(DNSZone(zone: zName, nameservers: servers))
                print("✔ Added corporate DNS zone: \(zName) → \(servers.joined(separator: ", "))")
            }
        }

        try ConfigStore.save(config)
        print("\n✔ Configuration updated in \(ConfigStore.fileURL.path)")
    }
}

// MARK: - Config

struct ConfigCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Read or modify RouteClue configuration",
        subcommands: [
            ConfigPath.self,
            ConfigShow.self,
            ConfigInit.self,
            ConfigAddSubnet.self,
            ConfigAddZone.self,
            ConfigSetProbe.self,
            ConfigSetDNS.self,
            ConfigSetIface.self,
        ],
        defaultSubcommand: ConfigShow.self
    )
}

struct ConfigPath: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "path", abstract: "Show path to config.json")
    func run() { print(ConfigStore.fileURL.path) }
}

struct ConfigShow: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "show", abstract: "Print config.json")
    func run() throws {
        let config = try ConfigStore.load()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(config), as: UTF8.self))
    }
}

struct ConfigInit: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "init", abstract: "Initialize default config file")
    func run() throws {
        let config = try ConfigStore.load()
        try ConfigStore.save(config)
        print("Config written to \(ConfigStore.fileURL.path)")
    }
}

struct ConfigAddSubnet: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "add-subnet", abstract: "Add subnet CIDR")
    @Argument(help: "Subnet CIDR (e.g. 10.0.0.0/8)") var cidr: String
    func run() throws {
        guard RouteManager.isValidSubnet(cidr) else {
            print("Error: Invalid CIDR subnet format '\(cidr)'")
            throw ExitCode(1)
        }
        var config = try ConfigStore.load()
        if !config.corpSubnets.contains(cidr) { config.corpSubnets.append(cidr) }
        try ConfigStore.save(config)
        print("Subnets: \(config.corpSubnets.joined(separator: ", "))")
    }
}

struct ConfigAddZone: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "add-zone", abstract: "Add DNS split zone")
    @Argument(help: "Zone domain name") var zone: String
    @Argument(help: "Nameserver IP addresses") var nameservers: [String]
    func run() throws {
        guard DNSZones.isValidZoneName(zone) else {
            print("Error: Invalid DNS zone domain name '\(zone)'")
            throw ExitCode(1)
        }
        for ns in nameservers {
            guard DNSZones.isValidNameserver(ns) else {
                print("Error: Invalid nameserver IP address '\(ns)'")
                throw ExitCode(1)
            }
        }
        var config = try ConfigStore.load()
        let entry = DNSZone(zone: zone, nameservers: nameservers)
        config.dnsZones.removeAll { $0.zone == zone }
        config.dnsZones.append(entry)
        try ConfigStore.save(config)
        print("Zone \(entry.zone) → \(entry.nameservers.joined(separator: ", "))")
    }
}

struct ConfigSetProbe: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "set-probe", abstract: "Set probe hostname")
    @Argument(help: "Hostname") var host: String
    func run() throws {
        var config = try ConfigStore.load()
        config.probeHosts = [host]
        try ConfigStore.save(config)
        print("Probe host: \(host)")
    }
}

struct ConfigSetDNS: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "set-dns", abstract: "Set allowed direct DNS")
    @Argument(help: "DNS Server IP") var server: String
    func run() throws {
        guard RouteManager.parseIPv4(server) != nil else {
            print("Error: Invalid IPv4 DNS server address '\(server)'")
            throw ExitCode(1)
        }
        var config = try ConfigStore.load()
        if !config.killSwitch.dnsAllow.contains(server) { config.killSwitch.dnsAllow.append(server) }
        try ConfigStore.save(config)
        print("Allowed DNS: \(config.killSwitch.dnsAllow.joined(separator: ", "))")
    }
}

struct ConfigSetIface: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "set-iface", abstract: "Set primary LAN interface")
    @Argument(help: "Interface name (e.g. en0)") var iface: String
    func run() throws {
        guard KillSwitch.isValidInterfaceName(iface) else {
            print("Error: Invalid interface name '\(iface)'")
            throw ExitCode(1)
        }
        var config = try ConfigStore.load()
        config.lanInterfaces = [iface]
        try ConfigStore.save(config)
        print("LAN interface: \(iface)")
    }
}
