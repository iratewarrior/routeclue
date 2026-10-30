import Foundation

public struct LANEndpoint: Sendable, Equatable, Codable {
    public let interface: String
    public let address: String
    public let gateway: String

    public init(interface: String, address: String, gateway: String) {
        self.interface = interface
        self.address = address
        self.gateway = gateway
    }
}

public struct RouteStatus: Sendable, Equatable, Codable {
    public let subnet: String
    public let gateway: String?
    public let interface: String?
    public let ifScoped: Bool
    public let expectedGateway: String?
    public let expectedInterface: String?

    public init(
        subnet: String,
        gateway: String?,
        interface: String?,
        ifScoped: Bool,
        expectedGateway: String? = nil,
        expectedInterface: String? = nil
    ) {
        self.subnet = subnet
        self.gateway = gateway
        self.interface = interface
        self.ifScoped = ifScoped
        self.expectedGateway = expectedGateway
        self.expectedInterface = expectedInterface
    }

    public var isOK: Bool {
        guard let gw = gateway, !gw.isEmpty, ifScoped else { return false }
        if let expGw = expectedGateway, !expGw.isEmpty, gw != expGw {
            return false
        }
        if let expIf = expectedInterface, !expIf.isEmpty, interface != expIf {
            return false
        }
        return true
    }
}

public struct ParsedNetstatRow: Sendable, Equatable {
    public let destination: String
    public let gateway: String
    public let flags: String
    public let interface: String
    public let expire: String?
    public let network: UInt32
    public let prefix: Int
    public let isUp: Bool
    public let isHost: Bool
    public let isGateway: Bool
    public let isScoped: Bool
    public let isLinkLayer: Bool

    public init(
        destination: String,
        gateway: String,
        flags: String,
        interface: String,
        expire: String?,
        network: UInt32,
        prefix: Int
    ) {
        self.destination = destination
        self.gateway = gateway
        self.flags = flags
        self.interface = interface
        self.expire = expire
        self.network = network
        self.prefix = prefix
        self.isUp = flags.contains("U")
        self.isHost = flags.contains("H")
        self.isGateway = flags.contains("G")
        self.isScoped = flags.contains("I")
        self.isLinkLayer = gateway.hasPrefix("link#")
    }
}

public enum RouteError: Error, CustomStringConvertible, Sendable {
    case invalidSubnet(String)
    case noGateway(String)

    public var description: String {
        switch self {
        case let .invalidSubnet(sub):
            return "Некорректный формат CIDR подсети: '\(sub)'. Ожидается формат 'A.B.C.D/M' (например, '10.20.0.0/16')."
        case let .noGateway(ifaces):
            return "Не найден LAN шлюз на интерфейсах: \(ifaces)"
        }
    }
}

/// Управление маршрутами к подсетям, которые должны идти в обход VPN-туннеля.
public enum RouteManager {
    /// Валидация строки CIDR (IPv4).
    public static func isValidSubnet(_ subnet: String) -> Bool {
        parseCIDR(subnet) != nil
    }

    /// Парсит IPv4 адрес без compactMap (строгая проверка октетов 0..255).
    public static func parseIPv4(_ dotted: String) -> UInt32? {
        let octets = dotted.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var bytes: [UInt32] = []
        for octet in octets {
            guard !octet.isEmpty && octet.allSatisfy(\.isNumber) else { return nil }
            guard let val = UInt32(octet), val <= 255 else { return nil }
            bytes.append(val)
        }
        return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]
    }

    /// Парсит CIDR (например, "10.20.0.0/16") в (network, prefix) со строгой проверкой каждого октета.
    public static func parseCIDR(_ cidr: String) -> (network: UInt32, prefix: Int)? {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              parts[1].allSatisfy(\.isNumber),
              let prefix = Int(parts[1]),
              prefix >= 0 && prefix <= 32 else { return nil }
        guard let ip = parseIPv4(String(parts[0])) else { return nil }
        let mask: UInt32 = prefix == 0 ? 0 : (~UInt32(0) << (32 - prefix))
        return (ip & mask, prefix)
    }

    /// Парсит строку назначения из вывода BSD netstat ("10", "169.254", "10.53/16", "2/7", "192.168.1", "default", с возможным %scope).
    public static func parseNetstatDestination(_ raw: String) -> (network: UInt32, prefix: Int)? {
        var str = raw
        if let pct = str.firstIndex(of: "%") {
            str = String(str[..<pct])
        }
        if str == "default" { return (0, 0) }

        if str.contains("/") {
            let parts = str.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  parts[1].allSatisfy(\.isNumber),
                  let prefix = Int(parts[1]),
                  prefix >= 0 && prefix <= 32 else { return nil }
            let octetStrings = parts[0].split(separator: ".", omittingEmptySubsequences: false)
            guard !octetStrings.isEmpty && octetStrings.count <= 4 else { return nil }
            var octets: [UInt32] = []
            for s in octetStrings {
                guard !s.isEmpty && s.allSatisfy(\.isNumber), let val = UInt32(s), val <= 255 else { return nil }
                octets.append(val)
            }
            while octets.count < 4 { octets.append(0) }
            let ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            let mask: UInt32 = prefix == 0 ? 0 : (~UInt32(0) << (32 - prefix))
            return (ip & mask, prefix)
        } else {
            let octetStrings = str.split(separator: ".", omittingEmptySubsequences: false)
            guard !octetStrings.isEmpty && octetStrings.count <= 4 else { return nil }
            var octets: [UInt32] = []
            for s in octetStrings {
                guard !s.isEmpty && s.allSatisfy(\.isNumber), let val = UInt32(s), val <= 255 else { return nil }
                octets.append(val)
            }
            let defaultPrefix: Int
            switch octets.count {
            case 1: defaultPrefix = 8
            case 2: defaultPrefix = 16
            case 3: defaultPrefix = 24
            case 4: defaultPrefix = 32
            default: return nil
            }
            while octets.count < 4 { octets.append(0) }
            let ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            let mask: UInt32 = defaultPrefix == 0 ? 0 : (~UInt32(0) << (32 - defaultPrefix))
            return (ip & mask, defaultPrefix)
        }
    }

    /// Парсит строки netstat таблицы: Destination Gateway Flags Netif [Expire].
    public static func parseNetstatRows(_ tableOutput: String) -> [ParsedNetstatRow] {
        var rows: [ParsedNetstatRow] = []
        for line in tableOutput.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard fields.count >= 4 else { continue }
            let destination = fields[0]
            guard let parsed = parseNetstatDestination(destination) else { continue }
            let gateway = fields[1]
            let flags = fields[2]
            guard flags.contains("U") else { continue } // Only UP routes
            let interface = fields[3]
            let expire = fields.count > 4 ? fields[4] : nil

            rows.append(
                ParsedNetstatRow(
                    destination: destination,
                    gateway: gateway,
                    flags: flags,
                    interface: interface,
                    expire: expire,
                    network: parsed.network,
                    prefix: parsed.prefix
                )
            )
        }
        return rows
    }

    public static func endpoints(_ config: RouteClueConfig) -> [LANEndpoint] {
        var result: [LANEndpoint] = []
        for iface in config.lanInterfaces {
            guard let address = try? Shell.run("/usr/sbin/ipconfig", ["getifaddr", iface]),
                  address.ok, !address.stdout.isEmpty,
                  let router = try? Shell.run("/usr/sbin/ipconfig", ["getoption", iface, "router"]),
                  router.ok, !router.stdout.isEmpty
            else { continue }
            result.append(LANEndpoint(interface: iface, address: address.stdout, gateway: router.stdout))
        }
        return result
    }

    public static func status(_ config: RouteClueConfig) -> [RouteStatus] {
        status(forSubnets: config.corpSubnets, config: config)
    }

    public static func status(forSubnets subnets: [String], config: RouteClueConfig) -> [RouteStatus] {
        let table = (try? Shell.run("/usr/sbin/netstat", ["-rn", "-f", "inet"]))?.stdout ?? ""
        return status(forSubnets: subnets, config: config, netstatOutput: table)
    }

    public static func status(forSubnets subnets: [String], config: RouteClueConfig, netstatOutput: String) -> [RouteStatus] {
        let rows = parseNetstatRows(netstatOutput)
        let expectedEndpoint = endpoints(config).first

        return subnets.map { subnet in
            guard let target = parseCIDR(subnet) else {
                return RouteStatus(
                    subnet: subnet,
                    gateway: nil,
                    interface: nil,
                    ifScoped: false,
                    expectedGateway: expectedEndpoint?.gateway,
                    expectedInterface: expectedEndpoint?.interface
                )
            }

            let match = rows.first { row in
                row.network == target.network && row.prefix == target.prefix
            }

            guard let row = match else {
                return RouteStatus(
                    subnet: subnet,
                    gateway: nil,
                    interface: nil,
                    ifScoped: false,
                    expectedGateway: expectedEndpoint?.gateway,
                    expectedInterface: expectedEndpoint?.interface
                )
            }

            return RouteStatus(
                subnet: subnet,
                gateway: row.isLinkLayer ? nil : row.gateway,
                interface: row.interface,
                ifScoped: row.isScoped,
                expectedGateway: expectedEndpoint?.gateway,
                expectedInterface: expectedEndpoint?.interface
            )
        }
    }

    /// Восстанавливает маршруты за один привилегированный запуск (один запрос Touch ID).
    @discardableResult
    public static func ensure(_ config: RouteClueConfig) throws -> [String] {
        guard !config.corpSubnets.isEmpty else { return ["No subnets configured."] }
        for subnet in config.corpSubnets {
            guard isValidSubnet(subnet) else {
                throw RouteError.invalidSubnet(subnet)
            }
        }

        guard let endpoint = endpoints(config).first else {
            throw RouteError.noGateway(config.lanInterfaces.joined(separator: ", "))
        }

        var commands: [String] = ["set -e"]
        for subnet in config.corpSubnets {
            let qSubnet = Shell.quote(subnet)
            let qGw = Shell.quote(endpoint.gateway)
            let qIf = Shell.quote(endpoint.interface)
            // route delete может вернуть ошибку, если маршрута не существовало — это допустимо
            commands.append("route delete -net \(qSubnet) >/dev/null 2>&1 || true")
            // route add ОБЯЗАН завершиться успешно, иначе batch останавливается немедленно
            commands.append("route add -net \(qSubnet) \(qGw) -ifscope \(qIf)")
        }

        let combined = commands.joined(separator: "\n")
        let result = try Shell.privileged(combined)

        var log = ["LAN \(endpoint.interface): \(endpoint.address) → \(endpoint.gateway)"]
        if result.ok {
            for subnet in config.corpSubnets {
                log.append("ok   \(subnet) → \(endpoint.gateway) (\(endpoint.interface), ifscope)")
            }
        } else {
            log.append("fail: \(result.combined)")
        }
        return log
    }

    /// Удаляет добавленные маршруты.
    @discardableResult
    public static func remove(_ config: RouteClueConfig) throws -> [String] {
        guard !config.corpSubnets.isEmpty else { return ["No subnets configured."] }
        for subnet in config.corpSubnets {
            guard isValidSubnet(subnet) else {
                throw RouteError.invalidSubnet(subnet)
            }
        }
        var commands = ["set -e"]
        for subnet in config.corpSubnets {
            commands.append("route delete -net \(Shell.quote(subnet)) >/dev/null 2>&1 || true")
        }
        let result = try Shell.privileged(commands.joined(separator: "\n"))
        return [result.ok ? "Routes removed." : "Failed: \(result.combined)"]
    }
}
