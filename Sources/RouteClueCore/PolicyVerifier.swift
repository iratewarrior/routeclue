import Foundation

public struct RouteCluePolicy: Sendable, Codable, Equatable {
    public var requireTunnelUp: Bool?
    public var requireKillSwitch: Bool?
    public var requiredSubnets: [String]?
    public var requiredResolvers: [String]?
    public var requiredZones: [String]?
    public var hostsDirect: [String]?
    public var hostsTunnel: [String]?
    public var hostsBlocked: [String]?

    public init(
        requireTunnelUp: Bool? = nil,
        requireKillSwitch: Bool? = nil,
        requiredSubnets: [String]? = nil,
        requiredResolvers: [String]? = nil,
        requiredZones: [String]? = nil,
        hostsDirect: [String]? = nil,
        hostsTunnel: [String]? = nil,
        hostsBlocked: [String]? = nil
    ) {
        self.requireTunnelUp = requireTunnelUp
        self.requireKillSwitch = requireKillSwitch
        self.requiredSubnets = requiredSubnets
        self.requiredResolvers = requiredResolvers
        self.requiredZones = requiredZones
        self.hostsDirect = hostsDirect
        self.hostsTunnel = hostsTunnel
        self.hostsBlocked = hostsBlocked
    }

    /// Генерирует политику по умолчанию на основе текущей конфигурации RouteClueConfig.
    public static func from(config: RouteClueConfig) -> RouteCluePolicy {
        RouteCluePolicy(
            requireTunnelUp: true,
            requiredSubnets: config.corpSubnets,
            requiredZones: config.dnsZones.filter { $0.enabled }.map(\.zone),
            hostsDirect: config.probeHosts
        )
    }
}

public typealias TGPolicy = RouteCluePolicy

public struct PolicyCheck: Sendable, Codable, Equatable {
    public let name: String
    public let passed: Bool
    public let detail: String

    public init(name: String, passed: Bool, detail: String) {
        self.name = name
        self.passed = passed
        self.detail = detail
    }
}

public struct PolicyReport: Sendable, Codable {
    public let allPassed: Bool
    public let checks: [PolicyCheck]

    public init(checks: [PolicyCheck]) {
        self.checks = checks
        self.allPassed = checks.allSatisfy(\.passed)
    }

    public var summary: String {
        var lines: [String] = []
        for check in checks {
            let symbol = check.passed ? "✔ PASS" : "✖ FAIL"
            lines.append("[\(symbol)] \(check.name): \(check.detail)")
        }
        lines.append("")
        lines.append(allPassed ? "Policy verification PASSED." : "Policy verification FAILED.")
        return lines.joined(separator: "\n")
    }
}

public enum PolicyVerifier {
    /// Проверяет соответствие состояния сети декларативной политике.
    /// Поддерживает инъекцию наблюдений (snapshot, killSwitch, resolver) для изоляции тестов от сети.
    public static func verify(
        policy: RouteCluePolicy,
        config: RouteClueConfig,
        snapshot: DiagnosticReport? = nil,
        killSwitchState: Bool?? = nil,
        installedZones: [String]? = nil,
        resolverTable: [ResolverInfo]? = nil,
        routeStatuses: [RouteStatus]? = nil,
        dnsProbe: (@Sendable (String, String) -> Bool)? = nil
    ) -> PolicyReport {
        var checks: [PolicyCheck] = []

        let snap = snapshot ?? Diagnostics.snapshot(config: config)
        let ks = (killSwitchState != nil) ? killSwitchState! : KillSwitch.isEnabled()

        if let requireTunnel = policy.requireTunnelUp {
            let ok = snap.tunnelUp == requireTunnel
            let detail = ok
                ? "Tunnel interface is \(snap.tunnelInterface ?? "up")"
                : "Expected tunnel \(requireTunnel ? "up" : "down"), but found \(snap.tunnelUp ? "up" : "down")"
            checks.append(PolicyCheck(name: "Tunnel state", passed: ok, detail: detail))
        }

        if let requireKillSwitch = policy.requireKillSwitch {
            if let activeKS = ks {
                let ok = activeKS == requireKillSwitch
                let detail = ok
                    ? "Kill switch is \(requireKillSwitch ? "on" : "off")"
                    : "Expected kill switch \(requireKillSwitch ? "on" : "off"), but found \(activeKS ? "on" : "off")"
                checks.append(PolicyCheck(name: "Kill switch state", passed: ok, detail: detail))
            } else {
                // Unknown is explicitly NOT treated as pass!
                checks.append(
                    PolicyCheck(
                        name: "Kill switch state",
                        passed: false,
                        detail: "Kill switch state is unknown (requires administrator privileges to inspect PF); unknown is not pass"
                    )
                )
            }
        }

        // Check required subnets directly in the routing table (even if not present in config.corpSubnets)
        if let subnets = policy.requiredSubnets {
            let statuses = routeStatuses ?? RouteManager.status(forSubnets: subnets, config: config)
            let routeMap = Dictionary(statuses.map { ($0.subnet, $0) }, uniquingKeysWith: { first, _ in first })
            for subnet in subnets {
                if let route = routeMap[subnet], route.isOK {
                    checks.append(PolicyCheck(name: "Route \(subnet)", passed: true, detail: "Via \(route.gateway ?? "") [\(route.interface ?? ""), ifscope]"))
                } else {
                    let reason = routeMap[subnet]?.gateway == nil ? "Route missing in routing table" : "Route lacks -ifscope or expected gateway"
                    checks.append(PolicyCheck(name: "Route \(subnet)", passed: false, detail: reason))
                }
            }
        }

        if let resolvers = policy.requiredResolvers {
            let sysResolvers = Set(snap.resolvers)
            for res in resolvers {
                let ok = sysResolvers.contains(res)
                checks.append(PolicyCheck(name: "Resolver \(res)", passed: ok, detail: ok ? "Configured in system" : "Missing in system resolvers"))
            }
        }

        // Check required zones against the real /etc/resolver configuration and DNS responses
        if let zones = policy.requiredZones {
            let installed = Set((installedZones ?? DNSZones.installedZones()).map { $0.lowercased() })
            let table = resolverTable ?? PathExplainer.resolverTable()
            let resolverMap = Dictionary(table.compactMap { info -> (String, ResolverInfo)? in
                guard let d = info.domain else { return nil }
                return (d.lowercased(), info)
            }, uniquingKeysWith: { first, _ in first })

            for zone in zones {
                let lowerZone = zone.lowercased()
                let isInstalled = installed.contains(lowerZone) || resolverMap[lowerZone] != nil
                if !isInstalled {
                    checks.append(PolicyCheck(name: "Zone \(zone)", passed: false, detail: "Not found in system /etc/resolver"))
                    continue
                }

                // Servers MUST ONLY come from actual resolver observations or actual file, NEVER falling back to expected config
                var servers = resolverMap[lowerZone]?.servers ?? []
                if servers.isEmpty, installed.contains(lowerZone) {
                    if let content = DNSZones.contents(of: zone) {
                        servers = content.split(separator: "\n")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { $0.hasPrefix("nameserver ") }
                            .map { String($0.dropFirst("nameserver ".count)).trimmingCharacters(in: .whitespaces) }
                    }
                }

                if servers.isEmpty {
                    // exists-but-no-servers / unknown case! Must NOT pass!
                    checks.append(PolicyCheck(name: "Zone \(zone)", passed: false, detail: "Zone is present in resolver observations or /etc/resolver, but has no actual nameservers configured"))
                    continue
                }

                let probeFn = dnsProbe ?? { name, server in
                    DNSQuery.a(name, server: server, timeout: 2)?.ok ?? false
                }
                let answers = servers.contains { probeFn("example.com", $0) }
                if answers {
                    checks.append(PolicyCheck(name: "Zone \(zone)", passed: true, detail: "Configured in resolver (servers: \(servers.joined(separator: ", ")))"))
                } else {
                    checks.append(PolicyCheck(name: "Zone \(zone)", passed: false, detail: "Resolver exists but DNS server is silent"))
                }
            }
        }

        if let directHosts = policy.hostsDirect {
            for host in directHosts {
                let explanation = PathExplainer.explain(host: host, config: config)
                let ok = explanation.verdict == .direct
                checks.append(PolicyCheck(name: "Direct host \(host)", passed: ok, detail: "Verdict: \(explanation.verdict.rawValue)"))
            }
        }

        if let tunnelHosts = policy.hostsTunnel {
            for host in tunnelHosts {
                let explanation = PathExplainer.explain(host: host, config: config)
                let ok = explanation.verdict == .viaTunnel
                checks.append(PolicyCheck(name: "Tunnel host \(host)", passed: ok, detail: "Verdict: \(explanation.verdict.rawValue)"))
            }
        }

        if let blockedHosts = policy.hostsBlocked {
            for host in blockedHosts {
                let explanation = PathExplainer.explain(host: host, config: config)
                // Фактический packet drop ядром PF не доказан без root testbed.
                // Не ставить passed: true только по прогнозу verdict == .blocked!
                checks.append(
                    PolicyCheck(
                        name: "Blocked host \(host)",
                        passed: false,
                        detail: "Фактическая блокировка ядром PF не проверена (прогноз политики: \(explanation.verdict.rawValue))"
                    )
                )
            }
        }

        return PolicyReport(checks: checks)
    }
}
