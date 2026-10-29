import Foundation

public struct ResolverInfo: Sendable, Equatable {
    public let domain: String?
    public let servers: [String]
    public let order: Int

    public init(domain: String?, servers: [String], order: Int = 0) {
        self.domain = domain
        self.servers = servers
        self.order = order
    }
}

public struct IPPath: Sendable, Equatable {
    public let address: String
    public let interface: String?
    public let gateway: String?
    public let ifScoped: Bool
    public let sourceAddress: String?
    public let warning: String?
}

public struct PathExplanation: Sendable {
    public let host: String
    public let resolverDomain: String?
    public let resolverServers: [String]
    public let addresses: [String]
    public let dnsError: String?
    public let paths: [IPPath]
    public let killSwitchEnabled: Bool?
    public let tunnelUp: Bool
    public let verdict: Verdict
    public let notes: [String]

    public enum Verdict: String, Sendable {
        case viaTunnel = "through the tunnel"
        case direct = "direct (bypasses the tunnel)"
        case blocked = "blocked by policy"
        case dnsFailure = "broken: name does not resolve"
        case noRoute = "broken: no route"
        case loopback = "local (loopback)"
    }

    public var summary: String {
        var lines: [String] = []
        let resolver = resolverDomain.map { "scoped zone \($0)" } ?? "global resolver"
        lines.append("Host: \(host)")
        lines.append("DNS: \(resolver) → \(resolverServers.joined(separator: ", "))")
        if let dnsError {
            lines.append("DNS result: \(dnsError)")
        } else {
            lines.append("DNS result: \(addresses.joined(separator: ", "))")
        }
        for path in paths {
            let gw = path.gateway ?? "—"
            let iface = path.interface ?? "—"
            let scope = path.ifScoped ? "ifscope" : "no ifscope"
            lines.append("Path \(path.address): \(iface) → \(gw) [\(scope)], source \(path.sourceAddress ?? "—")")
            if let warning = path.warning { lines.append("  ! \(warning)") }
        }
        let ks = killSwitchEnabled.map { $0 ? "on" : "off" } ?? "unknown"
        lines.append("Kill switch: \(ks), tunnel: \(tunnelUp ? "up" : "down")")
        lines.append("Verdict: \(verdict.rawValue)")
        if !notes.isEmpty { lines.append(contentsOf: notes.map { "· \($0)" }) }
        return lines.joined(separator: "\n")
    }
}

/// Explains the full path a connection takes on macOS: which resolver answers,
/// which route wins, which source address is used, and whether policy would block it.
public enum PathExplainer {
    public static func explain(host: String, config: TGConfig) -> PathExplanation {
        var notes: [String] = []

        let table = resolverTable()
        let scoped = bestResolver(for: host, in: table)
        let servers = scoped?.servers ?? globalServers(table)
        if scoped == nil, !config.dnsZones.isEmpty {
            notes.append("Name is outside the configured zones — a public resolver is asked.")
        }

        // What applications actually get (mDNSResponder: hosts file + scoped resolvers).
        let systemAddresses = systemResolvedAddresses(host)
        // What the chosen DNS server answers when asked directly.
        var rawAddresses: [String] = []
        var rawError: String?
        var lastError = "no answer"
        for server in servers {
            guard let answer = DNSQuery.a(host, server: server, timeout: 2) else {
                lastError = "no response from \(server)"
                continue
            }
            if answer.ok, !answer.addresses.isEmpty {
                rawAddresses = answer.addresses
                break
            }
            lastError = answer.rcode == 3 ? "NXDOMAIN from \(server)" : "rcode \(answer.rcode) from \(server)"
        }
        if rawAddresses.isEmpty { rawError = lastError }

        let addresses = systemAddresses.isEmpty ? rawAddresses : systemAddresses
        var dnsError: String?
        if addresses.isEmpty { dnsError = rawError ?? "no answer" }

        if !systemAddresses.isEmpty, rawAddresses.isEmpty {
            notes.append("Applications resolve this name, but \(servers.first ?? "the resolver") does not answer directly — DNS is intercepted or cached.")
        }
        if systemAddresses.isEmpty, !rawAddresses.isEmpty {
            notes.append("The DNS server answers, but the system resolver returns nothing — check /etc/resolver and the hosts file.")
        }
        if let hostsEntry = hostsFileAddress(host) {
            notes.append("Name is pinned in /etc/hosts to \(hostsEntry).")
        }

        let routes = routeTable()
        let primary = primaryInterface()
        let killSwitch = KillSwitch.isEnabled()
        let tunnel = Diagnostics.tunnelInterface(prefix: config.tunnelPrefix, defaultInterface: Diagnostics.defaultRouteInterface())
        let tunnelUp = tunnel != nil

        var paths: [IPPath] = []
        for address in addresses {
            let match = longestPrefixMatch(address, routes: routes)
            let iface = match?.interface
            let source = iface.flatMap { interfaceAddress($0) }
            var warning: String?
            if let iface, let tunnel, iface.hasPrefix(config.tunnelPrefix) == false, primary == tunnel, source == interfaceAddress(tunnel) {
                warning = "Route is direct but the source address belongs to the tunnel — add -ifscope."
            } else if let match, !match.ifScoped, let iface, iface != primary, iface.hasPrefix(config.tunnelPrefix) == false {
                warning = "Interface differs from the default route and the route is not ifscope-scoped."
            }
            paths.append(
                IPPath(
                    address: address,
                    interface: iface,
                    gateway: match?.gateway,
                    ifScoped: match?.ifScoped ?? false,
                    sourceAddress: source,
                    warning: warning
                )
            )
        }

        let verdict: PathExplanation.Verdict
        if !addresses.isEmpty, addresses.allSatisfy({ $0.hasPrefix("127.") }) {
            verdict = .loopback
        } else if addresses.isEmpty {
            verdict = .dnsFailure
        } else if paths.allSatisfy({ $0.interface == nil }) {
            verdict = .noRoute
        } else if killSwitch == true, !addresses.contains(where: { allowedByPolicy($0, config: config) }) {
            verdict = .blocked
        } else if paths.contains(where: { $0.interface?.hasPrefix(config.tunnelPrefix) == true }) {
            verdict = .viaTunnel
        } else {
            verdict = .direct
        }

        if killSwitch == true, verdict == .blocked {
            notes.append("Kill switch is on and the destination is outside the allow policy.")
        }

        return PathExplanation(
            host: host,
            resolverDomain: scoped?.domain,
            resolverServers: servers,
            addresses: addresses,
            dnsError: dnsError,
            paths: paths,
            killSwitchEnabled: killSwitch,
            tunnelUp: tunnelUp,
            verdict: verdict,
            notes: notes
        )
    }

    /// Whether a direct connection to this address is permitted by the configured policy.
    public static func allowedByPolicy(_ address: String, config: TGConfig) -> Bool {
        var prefixes = config.killSwitch.allowNets + config.killSwitch.extraAllow
        if let path = config.killSwitch.allowListPath,
           let text = try? String(contentsOfFile: path, encoding: .utf8) {
            prefixes += text.split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        }
        guard let ip = ipv4Value(address) else { return false }
        for prefix in prefixes {
            let parts = prefix.split(separator: "/")
            guard let bits = parts.count == 2 ? Int(parts[1]) : (prefix.contains(".") ? 32 : nil),
                  let network = networkValue(String(parts[0]), bits: bits)
            else { continue }
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
            if ip & mask == network { return true }
        }
        return false
    }

    // MARK: - System resolution

    /// Addresses as seen by applications (mDNSResponder), including hosts file and scoped resolvers.
    public static func systemResolvedAddresses(_ host: String) -> [String] {
        guard let result = try? Shell.run("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", host]), result.ok
        else { return [] }
        return result.stdout.split(separator: "\n").compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("ip_address:") else { return nil }
            return trimmed.replacingOccurrences(of: "ip_address:", with: "").trimmingCharacters(in: .whitespaces)
        }
    }

    public static func hostsFileAddress(_ host: String) -> String? {
        guard let text = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            let body = line.split(separator: "#").first.map(String.init) ?? ""
            let parts = body.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard parts.count >= 2 else { continue }
            if parts.dropFirst().contains(host) { return parts[0] }
        }
        return nil
    }

    // MARK: - Resolvers

    public static func resolverTable() -> [ResolverInfo] {
        guard let result = try? Shell.run("/usr/sbin/scutil", ["--dns"]) else { return [] }
        var infos: [ResolverInfo] = []
        var domain: String?
        var servers: [String] = []
        var order = 0

        func flush() {
            if !servers.isEmpty { infos.append(ResolverInfo(domain: domain, servers: servers, order: order)) }
            domain = nil
            servers = []
            order = 0
        }

        for raw in result.stdout.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("resolver #") { flush(); continue }
            if line.hasPrefix("domain :") {
                domain = line.replacingOccurrences(of: "domain :", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("nameserver[") {
                if let value = line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) {
                    servers.append(value)
                }
            } else if line.hasPrefix("order :") {
                order = Int(line.replacingOccurrences(of: "order :", with: "").trimmingCharacters(in: .whitespaces)) ?? 0
            }
        }
        flush()
        return infos
    }

    /// Longest matching zone wins, as mDNSResponder does.
    public static func bestResolver(for host: String, in table: [ResolverInfo]) -> ResolverInfo? {
        table
            .filter { info in
                guard let domain = info.domain else { return false }
                return host == domain || host.hasSuffix("." + domain)
            }
            .max { lhs, rhs in
                (lhs.domain?.count ?? 0) < (rhs.domain?.count ?? 0)
            }
    }

    public static func globalServers(_ table: [ResolverInfo]) -> [String] {
        table.first { $0.domain == nil }?.servers ?? []
    }

    // MARK: - Routes

    public struct RouteEntry: Sendable, Equatable {
        public let destination: String
        public let gateway: String?
        public let interface: String
        public let ifScoped: Bool

        public init(destination: String, gateway: String?, interface: String, ifScoped: Bool) {
            self.destination = destination
            self.gateway = gateway
            self.interface = interface
            self.ifScoped = ifScoped
        }
    }

    public static func routeTable() -> [RouteEntry] {
        guard let result = try? Shell.run("/usr/sbin/netstat", ["-rn", "-f", "inet"]) else { return [] }
        var entries: [RouteEntry] = []
        for line in result.stdout.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard fields.count >= 4 else { continue }
            let destination = fields[0]
            guard destination == "default" || destination.contains("/") else { continue }
            let flags = fields[2]
            guard flags.contains("U") else { continue }
            let iface = fields.last ?? ""
            guard iface.hasPrefix("en") || iface.hasPrefix("utun") || iface.hasPrefix("tun") else { continue }
            entries.append(
                RouteEntry(
                    destination: destination,
                    gateway: fields[1] == "link#1" ? nil : fields[1],
                    interface: iface,
                    ifScoped: flags.contains("I")
                )
            )
        }
        return entries
    }

    public static func longestPrefixMatch(_ address: String, routes: [RouteEntry]) -> RouteEntry? {
        guard let ip = ipv4Value(address) else { return routes.first { $0.destination == "default" } }
        var best: (RouteEntry, Int)?
        for route in routes {
            if route.destination == "default" {
                if best == nil { best = (route, 0) }
                continue
            }
            let parts = route.destination.split(separator: "/")
            guard parts.count == 2, let bits = Int(parts[1]), let network = networkValue(String(parts[0]), bits: bits) else { continue }
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
            if ip & mask == network, bits > (best?.1 ?? -1) {
                best = (route, bits)
            }
        }
        return best?.0
    }

    public static func networkValue(_ dotted: String, bits: Int) -> UInt32? {
        let padded = dotted.split(separator: ".").map(String.init) + Array(repeating: "0", count: max(0, 4 - dotted.split(separator: ".").count))
        guard let value = ipv4Value(padded.joined(separator: ".")) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        return value & mask
    }

    public static func ipv4Value(_ dotted: String) -> UInt32? {
        let parts = dotted.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 < 256 }) else { return nil }
        return parts.reduce(0) { ($0 << 8) | $1 }
    }

    // MARK: - Interfaces

    public static func interfaceAddress(_ name: String) -> String? {
        guard let result = try? Shell.run("/sbin/ifconfig", [name]), result.ok else { return nil }
        for line in result.stdout.split(separator: "\n") where line.contains("inet ") {
            // ifconfig indents lines with a tab, so split on any whitespace
            let parts = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            if let index = parts.firstIndex(of: "inet"), parts.count > index + 1 {
                return parts[index + 1]
            }
        }
        return nil
    }

    public static func primaryInterface() -> String? {
        guard let result = try? Shell.run("/usr/sbin/scutil", ["--nwi"]) else { return nil }
        for line in result.stdout.split(separator: "\n") where line.contains("Network interfaces:") {
            return line.replacingOccurrences(of: "Network interfaces:", with: "")
                .trimmingCharacters(in: .whitespaces)
                .split(separator: " ")
                .first
                .map(String.init)
        }
        return nil
    }
}
