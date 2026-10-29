import Foundation
import TunnelGuardCore

/// Dependency-free self test: runs with Command Line Tools only (no XCTest, no Testing).
/// Exits non-zero on the first failing check.

var failures = 0
var checks = 0

func expect(_ condition: Bool, _ message: String) {
    checks += 1
    if !condition {
        failures += 1
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
    }
}

func expectEqual<T: Equatable>(_ lhs: T, _ rhs: T, _ message: String) {
    expect(lhs == rhs, "\(message) — got \(lhs), expected \(rhs)")
}

func sampleConfig() -> TGConfig {
    TGConfig(
        corpSubnets: ["198.51.100.0/24"],
        dnsZones: [DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10"])],
        killSwitch: KillSwitchSettings(
            allowNets: ["10.0.0.0/8", "192.168.0.0/16"],
            extraAllow: ["203.0.113.10/32"],
            dnsAllow: ["10.0.0.10"]
        )
    )
}

// MARK: - Kill switch ruleset

let plan = KillSwitch.plan(config: sampleConfig(), interfaces: ["en0"], anchors: ["anchor \"com.apple/*\""])
expect(plan.rules.contains("pass out quick on en0 inet user = 0 keep state"), "tunnel core is allowed")
expect(plan.rules.contains("port 53 keep state"), "DNS rule is present")
expect(plan.rules.contains("block drop out quick on en0 inet all"), "fallback block is present")
expect(plan.rules.contains("anchor \"com.apple/*\""), "system anchors are preserved")

if let pass = plan.rules.range(of: "user = 0"), let block = plan.rules.range(of: "block drop out quick on en0 inet all") {
    expect(pass.lowerBound < block.lowerBound, "allow rules precede the block rule")
}

for line in plan.rules.split(separator: "\n") where line.contains("port ") {
    expect(line.contains("proto"), "rule with a port declares proto: \(line)")
}

var broken = sampleConfig()
broken.killSwitch.allowListPath = "/nonexistent/list.zone"
expectEqual(KillSwitch.plan(config: broken, interfaces: ["en0"], anchors: []).warnings.count, 1, "missing allow-list warns")

// MARK: - DNS

let packet = DNSQuery.buildQuery(name: "c.example.com", id: 0x1234)
expectEqual(Array(packet.prefix(2)), [0x12, 0x34], "query id")
expectEqual(Array(packet.suffix(4)), [0x00, 0x01, 0x00, 0x01], "question type/class")

var answer: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
for label in "example.com".split(separator: ".") {
    answer.append(UInt8(label.utf8.count))
    answer.append(contentsOf: label.utf8)
}
answer.append(0)
answer.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
answer.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 10, 1, 2, 3])
expectEqual(DNSQuery.parseAddresses(answer), ["10.1.2.3"], "A record parsing")

// MARK: - Path explainer

let table = [
    ResolverInfo(domain: nil, servers: ["1.1.1.1"], order: 0),
    ResolverInfo(domain: "example.com", servers: ["10.0.0.1"], order: 1),
    ResolverInfo(domain: "corp.example.com", servers: ["10.0.0.10"], order: 2),
]
expectEqual(PathExplainer.bestResolver(for: "intranet.corp.example.com", in: table)?.domain, "corp.example.com", "longest zone wins")
expect(PathExplainer.bestResolver(for: "example.org", in: table) == nil, "public name has no scoped resolver")

let routes = [
    PathExplainer.RouteEntry(destination: "default", gateway: "192.0.2.1", interface: "en0", ifScoped: false),
    PathExplainer.RouteEntry(destination: "10.0.0.0/8", gateway: "192.0.2.1", interface: "en0", ifScoped: true),
    PathExplainer.RouteEntry(destination: "10.20.0.0/16", gateway: "10.255.0.1", interface: "utun3", ifScoped: false),
]
expectEqual(PathExplainer.longestPrefixMatch("10.20.5.5", routes: routes)?.interface, "utun3", "specific route wins")

let policy = TGConfig(killSwitch: KillSwitchSettings(allowNets: ["10.0.0.0/8"], allowListPath: nil, extraAllow: [], dnsAllow: []))
expect(PathExplainer.allowedByPolicy("10.1.2.3", config: policy), "private address allowed")
expect(!PathExplainer.allowedByPolicy("203.0.113.1", config: policy), "public address denied")

expectEqual(PathExplainer.networkValue("10.20.0.0", bits: 16), PathExplainer.networkValue("10.20.255.1", bits: 16), "16-bit masking")
expect(PathExplainer.networkValue("10.20.0.0", bits: 8) == PathExplainer.networkValue("10.21.0.0", bits: 8), "8-bit masking collapses both to 10.0.0.0")

// MARK: - Config

let config = sampleConfig()
let decoded = try JSONDecoder().decode(TGConfig.self, from: JSONEncoder().encode(config))
expectEqual(decoded.corpSubnets, config.corpSubnets, "config round trip")

let rendered = DNSZones.render(DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10", "10.0.0.11"]))
expect(rendered.contains("nameserver 10.0.0.10"), "resolver file lists nameserver")
expect(rendered.contains("timeout 2"), "resolver file sets timeout")

// MARK: - Result

if failures == 0 {
    print("Self test passed: \(checks) checks")
    exit(0)
} else {
    print("Self test failed: \(failures) of \(checks) checks")
    exit(1)
}
