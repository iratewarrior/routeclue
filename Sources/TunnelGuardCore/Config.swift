import Foundation

/// A DNS zone that must be resolved by specific (usually corporate) servers.
public struct DNSZone: Codable, Sendable, Identifiable, Hashable {
    public var id: String { zone }
    public var zone: String
    public var nameservers: [String]
    public var enabled: Bool

    public init(zone: String, nameservers: [String], enabled: Bool = true) {
        self.zone = zone
        self.nameservers = nameservers
        self.enabled = enabled
    }
}

public struct KillSwitchSettings: Codable, Sendable {
    /// Destinations every process may reach directly (LAN, private ranges, corp subnets).
    public var allowNets: [String]
    /// Optional file with extra prefixes that may bypass the tunnel (one CIDR per line).
    public var allowListPath: String?
    /// Additional hosts that must stay reachable (e.g. a corporate VPN gateway).
    public var extraAllow: [String]
    /// DNS servers reachable directly on port 53.
    public var dnsAllow: [String]

    public init(
        allowNets: [String] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"],
        allowListPath: String? = nil,
        extraAllow: [String] = [],
        dnsAllow: [String] = []
    ) {
        self.allowNets = allowNets
        self.allowListPath = allowListPath
        self.extraAllow = extraAllow
        self.dnsAllow = dnsAllow
    }
}

public struct TGConfig: Codable, Sendable {
    /// Subnets that must bypass the tunnel.
    public var corpSubnets: [String]
    /// Interfaces used to discover the LAN gateway.
    public var lanInterfaces: [String]
    /// Prefix of tunnel interfaces (utun, tun, tap, ...).
    public var tunnelPrefix: String
    /// Zones written to /etc/resolver.
    public var dnsZones: [DNSZone]
    public var killSwitch: KillSwitchSettings
    /// Hosts used by diagnostics to verify zone resolution.
    public var probeHosts: [String]

    public init(
        corpSubnets: [String] = [],
        lanInterfaces: [String] = ["en0"],
        tunnelPrefix: String = "utun",
        dnsZones: [DNSZone] = [],
        killSwitch: KillSwitchSettings = .init(),
        probeHosts: [String] = []
    ) {
        self.corpSubnets = corpSubnets
        self.lanInterfaces = lanInterfaces
        self.tunnelPrefix = tunnelPrefix
        self.dnsZones = dnsZones
        self.killSwitch = killSwitch
        self.probeHosts = probeHosts
    }
}

public enum ConfigStore {
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/TunnelGuard", isDirectory: true)
    }

    public static var fileURL: URL { directory.appendingPathComponent("config.json") }

    public static func load() -> TGConfig {
        guard let data = try? Data(contentsOf: fileURL),
              let config = try? JSONDecoder().decode(TGConfig.self, from: data)
        else { return TGConfig() }
        return config
    }

    public static func save(_ config: TGConfig) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(config).write(to: fileURL, options: .atomic)
    }
}
