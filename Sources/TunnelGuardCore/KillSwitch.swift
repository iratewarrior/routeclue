import Foundation

public struct KillSwitchPlan: Sendable, Equatable {
    public let rules: String
    public let interfaces: [String]
    public let warnings: [String]
}

/// A pf-based kill switch for macOS.
///
/// Rules are bound to the owner of the sockets rather than to the VPN server address:
/// tunnel clients run their core as root, so its traffic to any server is always allowed.
/// Everything else may only reach explicitly allowed destinations, so a dropped tunnel
/// cannot leak traffic through the physical interface.
public enum KillSwitch {
    public static let rulesPath = "/tmp/tunnelguard-pf.conf"

    public static func physicalInterfaces() -> [String] {
        let result = try? Shell.run("/sbin/ifconfig", ["-l"])
        return (result?.stdout ?? "")
            .split(separator: " ")
            .map(String.init)
            .filter { $0.hasPrefix("en") && Int($0.dropFirst(2)) != nil }
    }

    /// System anchors must be preserved, otherwise the macOS application firewall is disabled.
    public static func systemAnchors() -> [String] {
        guard let text = try? String(contentsOfFile: "/etc/pf.conf", encoding: .utf8) else {
            return [
                "scrub-anchor \"com.apple/*\"",
                "anchor \"com.apple/*\"",
                "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"",
            ]
        }
        let keywords = ["scrub-anchor", "nat-anchor", "rdr-anchor", "dummynet-anchor", "anchor", "load anchor"]
        return text.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { line in keywords.contains { line.hasPrefix($0) } }
    }

    public static func plan(
        config: TGConfig,
        interfaces: [String]? = nil,
        anchors: [String]? = nil
    ) -> KillSwitchPlan {
        let ifaces = interfaces ?? physicalInterfaces()
        let anchorLines = anchors ?? systemAnchors()
        var warnings: [String] = []

        var allowListPath: String?
        if let path = config.killSwitch.allowListPath {
            if FileManager.default.fileExists(atPath: path) {
                allowListPath = path
            } else {
                warnings.append("Allow-list file not found: \(path)")
            }
        }

        var lines: [String] = ["set skip on lo0"]
        lines.append(contentsOf: anchorLines)
        lines.append("")

        if let path = allowListPath {
            lines.append("table <allowlist> persist file \"\(path)\"")
            lines.append("")
        }

        for iface in ifaces {
            lines.append("# --- \(iface)")
            // Tunnel core runs as root: allow its traffic regardless of the server address.
            lines.append("pass out quick on \(iface) inet user = 0 keep state")
            lines.append("pass out quick on \(iface) inet6 user = 0 keep state")
            // DHCP and mDNS keep the network usable when switching Wi-Fi.
            lines.append("pass out quick on \(iface) proto udp from any port 68 to any port 67 keep state")
            lines.append("pass out quick on \(iface) proto udp to 224.0.0.251 port 5353 keep state")

            if !config.killSwitch.allowNets.isEmpty {
                lines.append("pass out quick on \(iface) inet to { \(config.killSwitch.allowNets.joined(separator: ", ")) } keep state")
            }
            if allowListPath != nil {
                lines.append("pass out quick on \(iface) inet to <allowlist> keep state")
            }
            if !config.killSwitch.extraAllow.isEmpty {
                lines.append("pass out quick on \(iface) inet to { \(config.killSwitch.extraAllow.joined(separator: ", ")) } keep state")
            }
            if !config.killSwitch.dnsAllow.isEmpty {
                let servers = config.killSwitch.dnsAllow.joined(separator: ", ")
                lines.append("pass out quick on \(iface) inet proto { tcp, udp } to { \(servers) } port 53 keep state")
            }

            lines.append("block drop out quick on \(iface) inet all")
            lines.append("block drop out quick on \(iface) inet6 all")
            lines.append("")
        }

        return KillSwitchPlan(rules: lines.joined(separator: "\n"), interfaces: ifaces, warnings: warnings)
    }

    /// Parses the ruleset without applying it. Returns pf error text, empty when the plan is valid.
    public static func validate(_ plan: KillSwitchPlan) -> String {
        try? plan.rules.write(toFile: rulesPath, atomically: true, encoding: .utf8)
        let result = try? Shell.run("/sbin/pfctl", ["-n", "-f", rulesPath])
        let noise = ["Use of -f option", "present in the main ruleset", "See /etc/pf.conf"]
        return (result?.combined ?? "")
            .split(separator: "\n")
            .map(String.init)
            .filter { line in !line.isEmpty && !noise.contains { line.contains($0) } }
            .joined(separator: "\n")
    }

    public static func apply(_ config: TGConfig) throws -> KillSwitchPlan {
        let plan = plan(config: config)
        guard !plan.interfaces.isEmpty else {
            throw ShellError.failed(
                command: "ifconfig",
                result: .init(status: 1, stdout: "", stderr: "No en* interfaces found")
            )
        }

        try plan.rules.write(toFile: rulesPath, atomically: true, encoding: .utf8)
        let problems = validate(plan)
        if !problems.isEmpty {
            throw ShellError.failed(command: "pfctl -n", result: .init(status: 1, stdout: "", stderr: problems))
        }

        let result = try Shell.privileged("pfctl -f \(rulesPath) && pfctl -E")
        if !result.ok { throw ShellError.failed(command: "pfctl -f", result: result) }
        return plan
    }

    public static func disable() throws -> String {
        let result = try Shell.privileged("pfctl -f /etc/pf.conf; pfctl -d")
        return result.ok ? "Kill switch disabled, macOS rules restored." : result.combined
    }

    /// nil means the state is unknown (no root privileges).
    public static func isEnabled() -> Bool? {
        guard let result = try? Shell.run("/sbin/pfctl", ["-s", "info"]), result.ok else { return nil }
        return result.stdout.contains("Status: Enabled")
    }
}
