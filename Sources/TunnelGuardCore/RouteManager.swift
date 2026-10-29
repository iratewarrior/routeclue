import Foundation

public struct LANEndpoint: Sendable, Equatable {
    public let interface: String
    public let address: String
    public let gateway: String
}

public struct RouteStatus: Sendable, Equatable {
    public let subnet: String
    public let gateway: String?
    public let interface: String?
    public let ifScoped: Bool

    public var isOK: Bool { gateway != nil && ifScoped }
}

/// Routes to subnets that must bypass the tunnel.
///
/// While a TUN is up the default route points into the tunnel, so those subnets become
/// unreachable. A route added without `-ifscope` may also send packets with the tunnel's
/// source address, which corporate networks usually drop silently.
public enum RouteManager {
    public static func endpoints(_ config: TGConfig) -> [LANEndpoint] {
        config.lanInterfaces.compactMap { iface in
            guard let address = try? Shell.run("/usr/sbin/ipconfig", ["getifaddr", iface]),
                  address.ok, !address.stdout.isEmpty,
                  let router = try? Shell.run("/usr/sbin/ipconfig", ["getoption", iface, "router"]),
                  router.ok, !router.stdout.isEmpty
            else { return nil }
            return LANEndpoint(interface: iface, address: address.stdout, gateway: router.stdout)
        }
    }

    public static func status(_ config: TGConfig) -> [RouteStatus] {
        let table = (try? Shell.run("/usr/sbin/netstat", ["-rn", "-f", "inet"]))?.stdout ?? ""
        let entries = table.split(separator: "\n").map { line -> [String] in
            line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        }

        return config.corpSubnets.map { subnet in
            let needle = subnet.replacingOccurrences(of: ".0/", with: "/")
            let match = entries.first { row in
                guard row.count >= 4 else { return false }
                return row[0] == needle || row[0] == subnet
            }
            guard let row = match, row.count >= 4 else {
                return RouteStatus(subnet: subnet, gateway: nil, interface: nil, ifScoped: false)
            }
            return RouteStatus(
                subnet: subnet,
                gateway: row[1],
                interface: row.count > 5 ? row[5] : nil,
                ifScoped: row[3].contains("I")
            )
        }
    }

    /// Recreates routes: removes stale entries and adds them with an interface scope.
    @discardableResult
    public static func ensure(_ config: TGConfig) throws -> [String] {
        guard !config.corpSubnets.isEmpty else { return ["No subnets configured."] }
        guard let endpoint = endpoints(config).first else {
            throw ShellError.failed(
                command: "ipconfig",
                result: .init(
                    status: 1,
                    stdout: "",
                    stderr: "No LAN gateway found on: \(config.lanInterfaces.joined(separator: ", "))"
                )
            )
        }

        var log = ["LAN \(endpoint.interface): \(endpoint.address) → \(endpoint.gateway)"]
        for subnet in config.corpSubnets {
            let command = "route delete -net \(subnet) >/dev/null 2>&1 || true; "
                + "route add -net \(subnet) \(endpoint.gateway) -ifscope \(endpoint.interface)"
            let result = try Shell.privileged(command)
            log.append(
                result.ok
                    ? "ok   \(subnet) → \(endpoint.gateway) (\(endpoint.interface), ifscope)"
                    : "fail \(subnet): \(result.combined)"
            )
        }
        return log
    }

    @discardableResult
    public static func remove(_ config: TGConfig) throws -> [String] {
        guard !config.corpSubnets.isEmpty else { return ["No subnets configured."] }
        let commands = config.corpSubnets
            .map { "route delete -net \($0) >/dev/null 2>&1 || true" }
            .joined(separator: "; ")
        let result = try Shell.privileged(commands)
        return [result.ok ? "Routes removed." : "Failed: \(result.combined)"]
    }
}
