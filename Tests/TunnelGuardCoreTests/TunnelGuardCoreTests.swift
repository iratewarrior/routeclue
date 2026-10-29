import Foundation
import Testing
@testable import TunnelGuardCore

private func sampleConfig() -> TGConfig {
    TGConfig(
        corpSubnets: ["198.51.100.0/24"],
        lanInterfaces: ["en0"],
        dnsZones: [DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10"])],
        killSwitch: KillSwitchSettings(
            allowNets: ["10.0.0.0/8", "192.168.0.0/16"],
            allowListPath: nil,
            extraAllow: ["203.0.113.10/32"],
            dnsAllow: ["10.0.0.10"]
        ),
        probeHosts: ["intranet.corp.example.com"]
    )
}

@Suite("Kill switch ruleset")
struct KillSwitchTests {
    @Test("Tunnel core is allowed, everything else is dropped")
    func ordering() {
        let plan = KillSwitch.plan(config: sampleConfig(), interfaces: ["en0"], anchors: ["anchor \"com.apple/*\""])
        let rules = plan.rules

        #expect(rules.contains("pass out quick on en0 inet user = 0 keep state"))
        #expect(rules.contains("pass out quick on en0 inet to { 10.0.0.0/8, 192.168.0.0/16 } keep state"))
        #expect(rules.contains("pass out quick on en0 inet proto { tcp, udp } to { 10.0.0.10 } port 53 keep state"))
        #expect(rules.contains("block drop out quick on en0 inet all"))
        #expect(rules.contains("anchor \"com.apple/*\""))

        let passIndex = rules.range(of: "user = 0")!.lowerBound
        let blockIndex = rules.range(of: "block drop out quick on en0 inet all")!.lowerBound
        #expect(passIndex < blockIndex)
    }

    @Test("Every rule with a port declares a protocol (pf rejects otherwise)")
    func portRulesNeedProtocol() {
        let plan = KillSwitch.plan(config: sampleConfig(), interfaces: ["en0", "en1"], anchors: [])
        for line in plan.rules.split(separator: "\n") where line.contains("port ") {
            #expect(line.contains("proto"), "Rule without proto: \(line)")
        }
    }

    @Test("Missing allow-list file produces a warning instead of a broken rule")
    func missingAllowList() {
        var config = sampleConfig()
        config.killSwitch.allowListPath = "/nonexistent/list.zone"
        let plan = KillSwitch.plan(config: config, interfaces: ["en0"], anchors: [])
        #expect(plan.warnings.count == 1)
        #expect(plan.warnings[0].contains("list.zone"))
    }
}

@Suite("DNS client")
struct DNSQueryTests {
    @Test("Query packet layout")
    func packetLayout() {
        let packet = DNSQuery.buildQuery(name: "c.example.com", id: 0x1234)
        #expect(Array(packet.prefix(2)) == [0x12, 0x34])
        #expect(Array(packet.suffix(4)) == [0x00, 0x01, 0x00, 0x01])
    }

    @Test("Parsing an A answer")
    func parseAnswer() {
        var data: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        for label in "example.com".split(separator: ".") {
            data.append(UInt8(label.utf8.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0)
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        data.append(contentsOf: [0xC0, 0x0C])
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x3C])
        data.append(contentsOf: [0x00, 0x04])
        data.append(contentsOf: [10, 1, 2, 3])

        #expect(DNSQuery.parseAddresses(data) == ["10.1.2.3"])
    }
}

@Suite("Configuration")
struct ConfigTests {
    @Test("Round trip through JSON")
    func roundTrip() throws {
        let config = TGConfig(
            corpSubnets: ["198.51.100.0/24"],
            dnsZones: [DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10", "10.0.0.11"])]
        )
        let decoded = try JSONDecoder().decode(TGConfig.self, from: JSONEncoder().encode(config))
        #expect(decoded.corpSubnets == config.corpSubnets)
        #expect(decoded.dnsZones.first?.nameservers == ["10.0.0.10", "10.0.0.11"])
    }

    @Test("Resolver file content")
    func resolverRendering() {
        let text = DNSZones.render(DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10", "10.0.0.11"]))
        #expect(text.contains("nameserver 10.0.0.10"))
        #expect(text.contains("nameserver 10.0.0.11"))
        #expect(text.contains("timeout 2"))
    }
}
