import Foundation

/// Split DNS for private zones via /etc/resolver, which mDNSResponder honours.
/// Note: `dig` and `nslookup` ignore these files — verify with `dscacheutil` or a real app.
public enum DNSZones {
    public static let directory = "/etc/resolver"

    public static func installedZones() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: directory))?
            .filter { !$0.hasPrefix(".") }
            .sorted() ?? []
    }

    public static func contents(of zone: String) -> String? {
        try? String(contentsOfFile: "\(directory)/\(zone)", encoding: .utf8)
    }

    public static func render(_ zone: DNSZone) -> String {
        var lines = zone.nameservers.map { "nameserver \($0)" }
        lines.append("search_order 1")
        lines.append("timeout 2")
        return lines.joined(separator: "\n") + "\n"
    }

    /// Brings /etc/resolver in sync with the configuration.
    @discardableResult
    public static func apply(_ zones: [DNSZone]) throws -> String {
        guard !zones.isEmpty else { return "No zones configured." }

        let staging = FileManager.default.temporaryDirectory.appendingPathComponent("tunnelguard-dns", isDirectory: true)
        try? FileManager.default.removeItem(at: staging)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)

        var commands = ["mkdir -p \(directory)"]
        var messages: [String] = []

        for zone in zones {
            if zone.enabled {
                let file = staging.appendingPathComponent(zone.zone)
                try render(zone).write(to: file, atomically: true, encoding: .utf8)
                commands.append("cp '\(file.path)' '\(directory)/\(zone.zone)' && chmod 644 '\(directory)/\(zone.zone)'")
                messages.append("+ \(zone.zone) → \(zone.nameservers.joined(separator: ", "))")
            } else {
                commands.append("rm -f '\(directory)/\(zone.zone)'")
                messages.append("- \(zone.zone) removed")
            }
        }
        commands.append("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true")

        let result = try Shell.privileged(commands.joined(separator: "; "))
        if !result.ok { throw ShellError.failed(command: "resolver", result: result) }
        return (messages + ["DNS cache flushed."]).joined(separator: "\n")
    }

    @discardableResult
    public static func remove(zone: String) throws -> String {
        let command = "rm -f '\(directory)/\(zone)'; dscacheutil -flushcache; "
            + "killall -HUP mDNSResponder 2>/dev/null || true"
        let result = try Shell.privileged(command)
        return result.ok ? "Zone \(zone) removed." : result.combined
    }

    public static func flush() throws {
        try Shell.privileged("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true")
    }
}
