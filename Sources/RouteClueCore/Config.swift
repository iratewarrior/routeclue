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

public struct KillSwitchSettings: Codable, Sendable, Equatable {
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

public struct RouteClueConfig: Codable, Sendable, Equatable {
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

public typealias TGConfig = RouteClueConfig
public typealias RCConfig = RouteClueConfig

public enum ConfigError: Error, LocalizedError, Sendable, Equatable {
    case corrupted(url: URL, details: String)

    public var errorDescription: String? {
        switch self {
        case let .corrupted(url, details):
            return "Configuration file at '\(url.path)' is corrupted and cannot be parsed: \(details)"
        }
    }
}

public struct ConfigStore: Sendable, Equatable {
    public let directory: URL
    public let legacyDirectory: URL

    public static let defaultDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/RouteClue", isDirectory: true)

    public static let defaultLegacyDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/TunnelGuard", isDirectory: true)

    public static let standard = ConfigStore()

    public init(
        directory: URL = ConfigStore.defaultDirectory,
        legacyDirectory: URL = ConfigStore.defaultLegacyDirectory
    ) {
        self.directory = directory
        self.legacyDirectory = legacyDirectory
    }

    public var fileURL: URL { directory.appendingPathComponent("config.json") }
    public var legacyFileURL: URL { legacyDirectory.appendingPathComponent("config.json") }

    public func load() throws -> RouteClueConfig {
        let fm = FileManager.default

        // 1. RouteClue config has highest precedence
        if fm.fileExists(atPath: fileURL.path) {
            do {
                let data = try Data(contentsOf: fileURL)
                return try JSONDecoder().decode(RouteClueConfig.self, from: data)
            } catch {
                throw ConfigError.corrupted(url: fileURL, details: error.localizedDescription)
            }
        }

        // 2. Read-only fallback to legacy TunnelGuard config
        if fm.fileExists(atPath: legacyFileURL.path) {
            do {
                let data = try Data(contentsOf: legacyFileURL)
                return try JSONDecoder().decode(RouteClueConfig.self, from: data)
            } catch {
                throw ConfigError.corrupted(url: legacyFileURL, details: error.localizedDescription)
            }
        }

        // 3. Fresh installation: defaults
        return RouteClueConfig()
    }

    public func save(_ config: RouteClueConfig) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(config).write(to: fileURL, options: .atomic)
    }

    // Static convenience delegating to standard or custom directory without global mutable state
    public static var directory: URL { standard.directory }
    public static var legacyDirectory: URL { standard.legacyDirectory }
    public static var fileURL: URL { standard.fileURL }
    public static var legacyFileURL: URL { standard.legacyFileURL }

    public static func load(from customDirectory: URL? = nil) throws -> RouteClueConfig {
        if let dir = customDirectory {
            return try ConfigStore(directory: dir, legacyDirectory: dir).load()
        }
        return try standard.load()
    }

    public static func save(_ config: RouteClueConfig, to customDirectory: URL? = nil) throws {
        if let dir = customDirectory {
            try ConfigStore(directory: dir, legacyDirectory: dir).save(config)
        } else {
            try standard.save(config)
        }
    }
}
