import Foundation

public struct ZoneCheck: Sendable, Codable, Equatable {
    public let zone: String
    public let nameservers: [String]
    public let serverAlive: Bool
    public let sampleHost: String?
    public let sampleAddresses: [String]
    public let latency: TimeInterval?

    public init(
        zone: String,
        nameservers: [String],
        serverAlive: Bool,
        sampleHost: String?,
        sampleAddresses: [String],
        latency: TimeInterval?
    ) {
        self.zone = zone
        self.nameservers = nameservers
        self.serverAlive = serverAlive
        self.sampleHost = sampleHost
        self.sampleAddresses = sampleAddresses
        self.latency = latency
    }
}

public struct DiagnosticReport: Sendable, Codable, Equatable {
    public let lanInterface: String?
    public let lanAddress: String?
    public let gateway: String?
    public let tunnelInterface: String?
    public let tunnelUp: Bool
    public let defaultInterface: String?
    public let resolvers: [String]
    public let routes: [RouteStatus]
    public let zones: [ZoneCheck]
    public let exitIP: String?
    public let notes: [String]

    public init(
        lanInterface: String?,
        lanAddress: String?,
        gateway: String?,
        tunnelInterface: String?,
        tunnelUp: Bool,
        defaultInterface: String?,
        resolvers: [String],
        routes: [RouteStatus],
        zones: [ZoneCheck],
        exitIP: String?,
        notes: [String]
    ) {
        self.lanInterface = lanInterface
        self.lanAddress = lanAddress
        self.gateway = gateway
        self.tunnelInterface = tunnelInterface
        self.tunnelUp = tunnelUp
        self.defaultInterface = defaultInterface
        self.resolvers = resolvers
        self.routes = routes
        self.zones = zones
        self.exitIP = exitIP
        self.notes = notes
    }

    public var summary: String {
        var lines: [String] = []
        lines.append("LAN: \(lanInterface ?? "—") \(lanAddress ?? "") → \(gateway ?? "no gateway")")
        lines.append("Tunnel: \(tunnelInterface ?? "not found") (\(tunnelUp ? "up" : "down")), default: \(defaultInterface ?? "—")")
        lines.append("System resolvers: \(resolvers.isEmpty ? "—" : resolvers.joined(separator: ", "))")
        for route in routes {
            let state = route.gateway == nil ? "missing" : (route.ifScoped ? "ok" : "no -ifscope")
            lines.append("Route \(route.subnet): \(route.gateway ?? "—") via \(route.interface ?? "—") [\(state)]")
        }
        for zone in zones {
            let alive = zone.serverAlive ? "answers" : "silent"
            let answer = zone.sampleAddresses.isEmpty ? "—" : zone.sampleAddresses.joined(separator: ", ")
            lines.append("Zone \(zone.zone): DNS \(alive), \(zone.sampleHost ?? "—") → \(answer)")
        }
        lines.append("Exit address: \(exitIP ?? "unknown")")
        if !notes.isEmpty { lines.append(contentsOf: notes.map { "· \($0)" }) }
        return lines.joined(separator: "\n")
    }
}

public enum Diagnostics {
    /// Neutral host used to check whether a DNS server answers at all.
    public static let livenessProbe = "example.com"

    public static func snapshot(config: TGConfig) -> DiagnosticReport {
        var notes: [String] = []

        let endpoint = RouteManager.endpoints(config).first
        let defaultInterface = defaultRouteInterface()
        let tunnel = tunnelInterface(prefix: config.tunnelPrefix, defaultInterface: defaultInterface)

        if let tunnel, defaultInterface != tunnel {
            notes.append("A tunnel exists but the default route bypasses it (\(defaultInterface ?? "—")).")
        }

        let routes = RouteManager.status(config)
        for route in routes where route.gateway != nil && !route.ifScoped {
            notes.append("Route \(route.subnet) has no -ifscope: packets may leave with the tunnel address.")
        }

        var zones: [ZoneCheck] = []
        for zone in config.dnsZones where zone.enabled {
            guard let server = zone.nameservers.first else { continue }
            let probe = DNSQuery.a(livenessProbe, server: server, timeout: 2)
            let sampleHost = config.probeHosts.first
            let sample = sampleHost.flatMap { DNSQuery.a($0, server: server, timeout: 2) }
            zones.append(
                ZoneCheck(
                    zone: zone.zone,
                    nameservers: zone.nameservers,
                    serverAlive: probe?.ok ?? false,
                    sampleHost: sampleHost,
                    sampleAddresses: sample?.addresses ?? [],
                    latency: probe?.elapsed
                )
            )
            if !(probe?.ok ?? false) {
                notes.append("DNS \(server) for zone \(zone.zone) does not answer — private names will not resolve.")
            }
        }

        return DiagnosticReport(
            lanInterface: endpoint?.interface,
            lanAddress: endpoint?.address,
            gateway: endpoint?.gateway,
            tunnelInterface: tunnel,
            tunnelUp: tunnel != nil,
            defaultInterface: defaultInterface,
            resolvers: systemResolvers(),
            routes: routes,
            zones: zones,
            exitIP: exitIP(),
            notes: notes
        )
    }

    public static func defaultRouteInterface() -> String? {
        guard let result = try? Shell.run("/sbin/route", ["-n", "get", "default"]) else { return nil }
        return result.stdout
            .split(separator: "\n")
            .first { $0.contains("interface:") }?
            .split(separator: ":")
            .last?
            .trimmingCharacters(in: .whitespaces)
    }

    /// The tunnel is the default-route interface when it looks like a tunnel;
    /// otherwise the first tunnel interface that owns a routable IPv4 address.
    public static func tunnelInterface(prefix: String, defaultInterface: String?) -> String? {
        if let defaultInterface, defaultInterface.hasPrefix(prefix) { return defaultInterface }
        guard let result = try? Shell.run("/sbin/ifconfig", ["-l"]) else { return nil }
        for name in result.stdout.split(separator: " ").map(String.init) where name.hasPrefix(prefix) {
            guard let info = try? Shell.run("/sbin/ifconfig", [name]), info.ok else { continue }
            for line in info.stdout.split(separator: "\n") where line.contains("inet ") {
                let parts = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
                if let index = parts.firstIndex(of: "inet"), parts.count > index + 1 {
                    let address = parts[index + 1]
                    if !address.isEmpty { return name }
                }
            }
        }
        return nil
    }

    public static func systemResolvers() -> [String] {
        guard let result = try? Shell.run("/usr/sbin/scutil", ["--dns"]) else { return [] }
        var seen = Set<String>()
        for line in result.stdout.split(separator: "\n") where line.contains("nameserver[") {
            if let colonIndex = line.firstIndex(of: ":") {
                let value = line[line.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
                if !value.isEmpty { seen.insert(String(value)) }
            }
        }
        return Array(seen).sorted()
    }

    public static func exitIP() -> String? {
        guard let result = try? Shell.run("/usr/bin/curl", ["-s", "--max-time", "6", "https://ident.me"]),
              result.ok, !result.stdout.isEmpty
        else { return nil }
        return result.stdout
    }
}
