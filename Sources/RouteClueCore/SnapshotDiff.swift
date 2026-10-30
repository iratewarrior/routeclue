import Foundation

public struct NetworkSnapshot: Sendable, Codable, Equatable {
    public let timestamp: Date
    public let lanInterface: String?
    public let lanAddress: String?
    public let gateway: String?
    public let tunnelInterface: String?
    public let tunnelUp: Bool
    public let defaultInterface: String?
    public let resolvers: [String]
    public let routes: [RouteStatus]
    public let exitIP: String?
    public let killSwitchActive: Bool?

    public init(report: DiagnosticReport, killSwitchActive: Bool?, timestamp: Date = Date()) {
        self.timestamp = timestamp
        self.lanInterface = report.lanInterface
        self.lanAddress = report.lanAddress
        self.gateway = report.gateway
        self.tunnelInterface = report.tunnelInterface
        self.tunnelUp = report.tunnelUp
        self.defaultInterface = report.defaultInterface
        self.resolvers = report.resolvers
        self.routes = report.routes
        self.exitIP = report.exitIP
        self.killSwitchActive = killSwitchActive
    }
}

public struct SnapshotDiff: Sendable, Codable {
    public let hasDrift: Bool
    public let changes: [String]
    public let addedResolvers: [String]
    public let removedResolvers: [String]
    public let changedRoutes: [String]

    public init(before: NetworkSnapshot, after: NetworkSnapshot) {
        var diffs: [String] = []

        if before.lanInterface != after.lanInterface {
            diffs.append("LAN Interface: \(before.lanInterface ?? "none") → \(after.lanInterface ?? "none")")
        }
        if before.gateway != after.gateway {
            diffs.append("Gateway: \(before.gateway ?? "none") → \(after.gateway ?? "none")")
        }
        if before.tunnelInterface != after.tunnelInterface || before.tunnelUp != after.tunnelUp {
            let bTun = "\(before.tunnelInterface ?? "none") (\(before.tunnelUp ? "up" : "down"))"
            let aTun = "\(after.tunnelInterface ?? "none") (\(after.tunnelUp ? "up" : "down"))"
            diffs.append("Tunnel: \(bTun) → \(aTun)")
        }
        if before.defaultInterface != after.defaultInterface {
            diffs.append("Default Route: \(before.defaultInterface ?? "none") → \(after.defaultInterface ?? "none")")
        }
        if before.exitIP != after.exitIP {
            diffs.append("Exit IP: \(before.exitIP ?? "unknown") → \(after.exitIP ?? "unknown")")
        }
        if before.killSwitchActive != after.killSwitchActive {
            let bKs = before.killSwitchActive.map { $0 ? "on" : "off" } ?? "unknown"
            let aKs = after.killSwitchActive.map { $0 ? "on" : "off" } ?? "unknown"
            diffs.append("Kill Switch: \(bKs) → \(aKs)")
        }

        let beforeRes = Set(before.resolvers)
        let afterRes = Set(after.resolvers)
        let addedRes = Array(afterRes.subtracting(beforeRes)).sorted()
        let removedRes = Array(beforeRes.subtracting(afterRes)).sorted()

        for res in addedRes { diffs.append("+ DNS Resolver: \(res)") }
        for res in removedRes { diffs.append("- DNS Resolver: \(res)") }

        var routeChanges: [String] = []
        // Safe against duplicate subnets in route tables
        let beforeMap = Dictionary(before.routes.map { ($0.subnet, $0) }, uniquingKeysWith: { first, _ in first })
        let afterMap = Dictionary(after.routes.map { ($0.subnet, $0) }, uniquingKeysWith: { first, _ in first })
        let allSubnets = Set(beforeMap.keys).union(afterMap.keys).sorted()

        for subnet in allSubnets {
            let b = beforeMap[subnet]
            let a = afterMap[subnet]
            if let b, let a {
                if b != a {
                    let msg = "Route \(subnet): \(b.gateway ?? "none")(\(b.ifScoped ? "ifscope" : "no-scope")) → \(a.gateway ?? "none")(\(a.ifScoped ? "ifscope" : "no-scope"))"
                    routeChanges.append(msg)
                    diffs.append(msg)
                }
            } else if let b = b {
                let msg = "- Route \(subnet): was via \(b.gateway ?? "none")"
                routeChanges.append(msg)
                diffs.append(msg)
            } else if let a = a {
                let msg = "+ Route \(subnet): now via \(a.gateway ?? "none")"
                routeChanges.append(msg)
                diffs.append(msg)
            }
        }

        self.hasDrift = !diffs.isEmpty
        self.changes = diffs
        self.addedResolvers = addedRes
        self.removedResolvers = removedRes
        self.changedRoutes = routeChanges
    }

    public var summary: String {
        if !hasDrift {
            return "No network drift detected. State is identical."
        }
        return (["Detected network drift:"] + changes.map { "  • \($0)" }).joined(separator: "\n")
    }
}
