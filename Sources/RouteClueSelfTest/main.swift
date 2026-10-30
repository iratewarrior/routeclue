import Foundation
import RouteClueCore

/// Dependency-free self test: runs with Command Line Tools only (no XCTest, no Testing).
/// Exits non-zero on the first failing check. All tests are strictly isolated from the live network.

var failures = 0
var checks = 0

@MainActor
func expect(_ condition: Bool, _ message: String) {
    checks += 1
    if !condition {
        failures += 1
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
    }
}

@MainActor
func expectEqual<T: Equatable>(_ lhs: T, _ rhs: T, _ message: String) {
    expect(lhs == rhs, "\(message) — got \(lhs), expected \(rhs)")
}

func sampleConfig() -> RouteClueConfig {
    RouteClueConfig(
        corpSubnets: ["198.51.100.0/24", "10.20.0.0/16"],
        dnsZones: [DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10", "10.0.0.11"])],
        killSwitch: KillSwitchSettings(
            allowNets: ["10.0.0.0/8", "192.168.0.0/16"],
            extraAllow: ["203.0.113.10/32"],
            dnsAllow: ["10.0.0.10"]
        ),
        probeHosts: ["intranet.corp.example.com"]
    )
}

// MARK: - 1. TargetInputNormalizer (URL secrets, IPv6, ports)

// Secret / credentials stripping
let secretUrl = "https://admin:superSecretToken99@internal.corp.com:8443/api/v1?token=abc#frag"
switch TargetInputNormalizer.normalize(secretUrl) {
case let .success(host):
    expectEqual(host, "internal.corp.com", "URL userinfo/secrets stripped and port removed")
case let .failure(err):
    expect(false, "Failed to normalize secret URL: \(err)")
}

// Malformed URL with credentials does NOT echo secrets in error description
let malformedSecretUrl = "https://admin:SuperSecretPassword123@%malformed-host%"
switch TargetInputNormalizer.normalize(malformedSecretUrl) {
case .success:
    expect(false, "Malformed URL should fail")
case let .failure(err):
    expect(!err.localizedDescription.contains("SuperSecretPassword123"), "Error description does NOT leak user credentials/secrets")
}

// Case-insensitivity normalization to lowercase
switch TargetInputNormalizer.normalize("HTTP://CORP.EXAMPLE.COM:8080/PATH") {
case let .success(host):
    expectEqual(host, "corp.example.com", "Hostname normalized to lowercase")
case let .failure(err):
    expect(false, "Failed to normalize uppercase host: \(err)")
}

// Case-insensitive bestResolver matching
let caseResolver = PathExplainer.bestResolver(
    for: "INTRANET.CORP.EXAMPLE.COM",
    in: [ResolverInfo(domain: "corp.example.com", servers: ["10.0.0.10"])]
)
expectEqual(caseResolver?.servers.first, "10.0.0.10", "bestResolver matches host and domain case-insensitively")

// Raw unbracketed IPv6 (must NOT be truncated at colon)
let rawIPv6 = "2001:db8::1"
switch TargetInputNormalizer.normalize(rawIPv6) {
case let .success(host):
    expectEqual(host, "2001:db8::1", "Raw IPv6 preserved without split(:) truncation")
case let .failure(err):
    expect(false, "Failed to normalize raw IPv6: \(err)")
}

// Bracketed IPv6 with port and path
let bracketedIPv6 = "http://[2001:db8:85a3::8a2e:370:7334]:8080/status"
switch TargetInputNormalizer.normalize(bracketedIPv6) {
case let .success(host):
    expectEqual(host, "2001:db8:85a3::8a2e:370:7334", "Bracketed IPv6 extracted correctly without port")
case let .failure(err):
    expect(false, "Failed to normalize bracketed IPv6: \(err)")
}

// Host:port and IPv4:port
switch TargetInputNormalizer.normalize("192.168.1.1:8080") {
case let .success(host):
    expectEqual(host, "192.168.1.1", "IPv4:port normalized")
case let .failure(err):
    expect(false, "Failed to normalize IPv4:port: \(err)")
}

switch TargetInputNormalizer.normalize("example.com:443") {
case let .success(host):
    expectEqual(host, "example.com", "example.com:443 normalized")
case let .failure(err):
    expect(false, "Failed to normalize host:port: \(err)")
}

// Syntax validation fails immediately without DNS
switch TargetInputNormalizer.normalize("invalid_host!@#") {
case .success:
    expect(false, "Invalid characters in hostname must fail immediately")
case .failure:
    expect(true, "Invalid host caught before DNS")
}

switch TargetInputNormalizer.normalize("") {
case .success:
    expect(false, "Empty string must fail")
case let .failure(err):
    expectEqual(err, .emptyInput, "Empty input caught")
}

// MARK: - 2. KillSwitch Ruleset & Active Ruleset Reachability

do {
    let plan = try KillSwitch.plan(config: sampleConfig(), interfaces: ["en0"], anchors: ["anchor \"com.apple/*\""])
    expect(plan.rules.contains("pass out quick on en0 inet user = 0 keep state"), "tunnel core root is allowed")
    expect(plan.rules.contains("port 53 keep state"), "DNS rule is present")
    expect(plan.rules.contains("block drop out quick on en0 inet all"), "fallback block is present")
    expect(plan.rules.contains("anchor \"com.apple/*\""), "system anchors are preserved")
    expect(plan.rules.contains("proto ipv6-icmp to { ff02::/16, fe80::/10 }"), "ICMPv6 neighbor discovery rule is present")
} catch {
    expect(false, "KillSwitch.plan failed: \(error)")
}

// Strict reachability validation against active ruleset (pfctl -sr)
// A: Valid active anchor calls
expect(KillSwitch.isAnchorReachable(inRuleset: "anchor \"com.apple/*\" all").reachable, "proven anchor 'com.apple/*' is reachable")
expect(KillSwitch.isAnchorReachable(inRuleset: "anchor \"com.apple/*\"").reachable, "proven anchor 'com.apple/*' without 'all' is reachable")
expect(KillSwitch.isAnchorReachable(inRuleset: "anchor \"com.apple/routeclue\" all").reachable, "exact anchor 'com.apple/routeclue' is reachable")

// B: Reject unproven, bare com.apple, bare rootless, comments, conditioned, or empty rules
expect(!KillSwitch.isAnchorReachable(inRuleset: "anchor \"com.apple\" all").reachable, "bare parent anchor 'com.apple' is rejected")
expect(!KillSwitch.isAnchorReachable(inRuleset: "").reachable, "disabled empty active rules fail closed")
expect(!KillSwitch.isAnchorReachable(inRuleset: "# anchor \"com.apple/*\" all").reachable, "commented anchor line is rejected")
expect(!KillSwitch.isAnchorReachable(inRuleset: "anchor \"com.apple/routeclue-rootless\" all").reachable, "bare routeclue-rootless anchor is rejected")
expect(!KillSwitch.isAnchorReachable(inRuleset: "block out quick on en0 anchor \"com.apple/*\"").reachable, "conditioned anchor line is rejected")

// AllowList with invalid entries fails
do {
    let tempAllow = FileManager.default.temporaryDirectory.appendingPathComponent("test-allow-\(UUID().uuidString).txt")
    try "10.0.0.1\nnot-a-cidr\n".write(to: tempAllow, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: tempAllow) }

    var badConfig = sampleConfig()
    badConfig.killSwitch.allowListPath = tempAllow.path
    do {
        _ = try KillSwitch.plan(config: badConfig, interfaces: ["en0"])
        expect(false, "KillSwitch.plan must throw on invalid allowList line")
    } catch KillSwitchError.allowListInvalidLine {
        expect(true, "KillSwitch.plan caught invalid allowList line")
    } catch {
        expect(false, "Unexpected error for bad allowList: \(error)")
    }
} catch {
    expect(false, "AllowList test setup failed: \(error)")
}

// AllowList inlining
do {
    let tempAllow = FileManager.default.temporaryDirectory.appendingPathComponent("test-allow-\(UUID().uuidString).txt")
    try "198.51.100.5\n203.0.113.0/24\n".write(to: tempAllow, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: tempAllow) }

    var goodConfig = sampleConfig()
    goodConfig.killSwitch.allowListPath = tempAllow.path
    let goodPlan = try KillSwitch.plan(config: goodConfig, interfaces: ["en0"])
    expect(goodPlan.rules.contains("table <allowlist> { 198.51.100.5, 203.0.113.0/24 }"), "allowList entries inlined as table")
} catch {
    expect(false, "Valid allowList test failed: \(error)")
}

// Production Script Harness with Fake pfctl (No sudo, isolated temp state)
struct FakePfctlHarness {
    let baseDir: URL
    let binDir: URL
    let pfctlPath: String
    let stateDir: URL
    let rulesFile: URL
    let eCountFile: URL
    let xCountFile: URL
    let loadedFile: URL
    let flushedFile: URL

    init() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-pfctl-\(UUID().uuidString)", isDirectory: true)
        self.baseDir = base
        self.binDir = base.appendingPathComponent("bin", isDirectory: true)
        self.stateDir = base.appendingPathComponent("state", isDirectory: true)
        self.rulesFile = base.appendingPathComponent("rules.txt")
        self.eCountFile = base.appendingPathComponent("e_count.txt")
        self.xCountFile = base.appendingPathComponent("x_count.txt")
        self.loadedFile = base.appendingPathComponent("loaded.txt")
        self.flushedFile = base.appendingPathComponent("flushed.txt")

        try FileManager.default.createDirectory(at: binDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)

        let scriptPath = binDir.appendingPathComponent("pfctl").path
        self.pfctlPath = scriptPath

        let defaultRules = """
        scrub-anchor "com.apple/*"
        anchor "com.apple/*" all
        load anchor "com.apple" from "/etc/pf.anchors/com.apple"
        """
        try defaultRules.write(to: rulesFile, atomically: true, encoding: .utf8)

        let script = """
        #!/bin/sh
        BASE="\(base.path)"
        RULES_FILE="$BASE/rules.txt"
        E_COUNT="$BASE/e_count.txt"
        X_COUNT="$BASE/x_count.txt"
        LOADED="$BASE/loaded.txt"
        FLUSHED="$BASE/flushed.txt"
        STATE="$BASE/state"

        if [ "$1" = "-sr" ]; then
            if [ "$FAKE_EMPTY_RULES" = "1" ]; then
                exit 0
            fi
            if [ "$FAKE_MISSING_ANCHOR" = "1" ]; then
                echo "block drop in all"
                exit 0
            fi
            if [ -f "$RULES_FILE" ]; then
                cat "$RULES_FILE"
            else
                echo 'anchor "com.apple/*" all'
            fi
            exit 0
        fi

        if [ "$1" = "-s" ] && [ "$2" = "info" ]; then
            if [ "$FAKE_PF_DISABLED" = "1" ]; then
                echo "Status: Disabled"
            else
                echo "Status: Enabled for 1 days 02:00:00"
            fi
            exit 0
        fi

        if [ "$1" = "-s" ] && [ "$2" = "References" ]; then
            if [ "$FAKE_EMPTY_REFS" = "1" ]; then
                exit 0
            fi
            if [ "$FAKE_SUFFIX_REFS" = "1" ]; then
                echo "Token: 19988  PID: 9999  Name: other_service"
                exit 0
            fi
            if [ "$FAKE_STALE_REFS" = "1" ]; then
                echo "Token: 11111111  PID: 9999  Name: other_service"
                exit 0
            fi
            if [ -f "$E_COUNT" ]; then
                CUR_E=$(cat "$E_COUNT")
                echo "Token: 99887766$CUR_E  PID: 1234  Name: routeclue"
            fi
            exit 0
        fi

        if [ "$1" = "-n" ]; then
            cat > /dev/null
            exit 0
        fi

        if [ "$1" = "-E" ]; then
            if [ "$FAKE_FAIL_E" = "1" ]; then
                echo "pfctl: failed to enable pf" >&2
                exit 1
            fi
            OLD_E=0
            if [ -f "$E_COUNT" ]; then
                OLD_E=$(cat "$E_COUNT")
            fi
            NEW_E=$((OLD_E + 1))
            echo "$NEW_E" > "$E_COUNT"
            echo "pf enabled" >&2
            echo "Token : 99887766$NEW_E" >&2
            if [ "$FAKE_CHMOD_READONLY_AFTER_E" = "1" ]; then
                chmod 500 "$STATE" 2>/dev/null || true
            fi
            exit 0
        fi

        if [ "$1" = "-X" ]; then
            if [ "$FAKE_FAIL_X" = "1" ]; then
                echo "pfctl: failed to release token $2" >&2
                exit 1
            fi
            OLD_X=0
            if [ -f "$X_COUNT" ]; then
                OLD_X=$(cat "$X_COUNT")
            fi
            NEW_X=$((OLD_X + 1))
            echo "$NEW_X" > "$X_COUNT"
            echo "Token $2 released" >&2
            if [ "$FAKE_CHMOD_READONLY_DURING_X" = "1" ]; then
                chmod 500 "$STATE" 2>/dev/null || true
            fi
            exit 0
        fi

        if [ "$1" = "-a" ] && [ "$3" = "-F" ] && [ "$4" = "rules" ]; then
            if [ "$FAKE_FAIL_FLUSH" = "1" ]; then
                echo "pfctl: failed to flush anchor $2" >&2
                exit 1
            fi
            echo "$2" >> "$FLUSHED"
            exit 0
        fi

        if [ "$1" = "-a" ] && [ "$3" = "-f" ]; then
            if [ "$FAKE_FAIL_LOAD" = "1" ]; then
                echo "pfctl: failed to load rules into anchor $2" >&2
                exit 1
            fi
            echo "$2:$4" >> "$LOADED"
            exit 0
        fi

        echo "pfctl: unknown options: $@" >&2
        exit 0
        """

        try script.write(to: binDir.appendingPathComponent("pfctl"), atomically: true, encoding: .utf8)
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptPath)
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: baseDir)
    }

    func eCount() -> Int {
        guard let s = try? String(contentsOf: eCountFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let val = Int(s) else { return 0 }
        return val
    }

    func xCount() -> Int {
        guard let s = try? String(contentsOf: xCountFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let val = Int(s) else { return 0 }
        return val
    }
}

// 2.1 Repeat on: single token reference acquired, subsequent apply reuses active token
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let script1 = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let res1 = try Shell.sh(script1)
    expect(res1.ok, "First apply script succeeds")
    expectEqual(harness.eCount(), 1, "First apply acquires exactly 1 reference token")
    let tokenPath = harness.stateDir.appendingPathComponent("pf-token").path
    expect(FileManager.default.fileExists(atPath: tokenPath), "Token file written to state directory")

    // Second apply with same state directory
    let res2 = try Shell.sh(script1)
    expect(res2.ok, "Second apply script succeeds")
    expectEqual(harness.eCount(), 1, "Repeat apply reuses token and acquires 0 additional references")
} catch {
    expect(false, "Repeat apply test failed: \(error)")
}

// 2.2 Concurrent on: blocked by active lock without duplicate token acquisition
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let lockDir = harness.stateDir.appendingPathComponent("lock")
    try FileManager.default.createDirectory(at: lockDir, withIntermediateDirectories: true)

    let script = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let res = try Shell.sh(script)
    expect(!res.ok, "Concurrent apply fails when lock is held")
    expectEqual(res.status, 2, "Concurrent apply returns exit code 2 (busy)")
    expect(res.stderr.contains("FAIL_LOCK"), "Concurrent apply outputs FAIL_LOCK")
    expectEqual(harness.eCount(), 0, "No token acquired when lock is busy")

    try FileManager.default.removeItem(at: lockDir)
    let resAfter = try Shell.sh(script)
    expect(resAfter.ok, "Apply succeeds after lock is released")
    expectEqual(harness.eCount(), 1, "Exactly 1 token acquired after lock is released")
} catch {
    expect(false, "Concurrent apply test failed: \(error)")
}

// 2.3 Concurrent apply / disable mutual exclusion
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let lockDir = harness.stateDir.appendingPathComponent("lock")
    try FileManager.default.createDirectory(at: lockDir, withIntermediateDirectories: true)

    let disableScript = KillSwitch.makeDisableScript(
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let res = try Shell.sh(disableScript)
    expect(!res.ok, "Disable fails when lock is held by concurrent apply")
    expectEqual(res.status, 2, "Disable returns exit code 2 when busy")
    expect(res.stderr.contains("FAIL_LOCK"), "Disable outputs FAIL_LOCK")

    try FileManager.default.removeItem(at: lockDir)
    let resFree = try Shell.sh(disableScript)
    expect(resFree.ok, "Disable succeeds when lock is free")
} catch {
    expect(false, "Concurrent apply/disable lock test failed: \(error)")
}

// 2.4 Failed pfctl -X preserves token file for subsequent recovery
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    _ = try Shell.sh(applyScript)
    let tokenFile = harness.stateDir.appendingPathComponent("pf-token")
    expect(FileManager.default.fileExists(atPath: tokenFile.path), "Token file present before disable")

    let disableScript = KillSwitch.makeDisableScript(
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let res = try Shell.sh(disableScript, environment: ["FAKE_FAIL_X": "1"])
    expect(!res.ok, "Disable script fails when pfctl -X fails")
    expectEqual(res.status, 4, "Disable script returns exit code 4 on release failure")
    expect(FileManager.default.fileExists(atPath: tokenFile.path), "Token file is preserved on failed release")
} catch {
    expect(false, "Failed -X token retention test failed: \(error)")
}

// 2.5 Save failure: compensating rollback or recovery token reported
do {
    let harness = try FakePfctlHarness()
    defer {
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: harness.stateDir.path)
        harness.cleanup()
    }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )

    // Subtest 1: Save fails via read-only stateDir after -E, compensating release succeeds
    let res1 = try Shell.sh(applyScript, environment: ["FAKE_CHMOD_READONLY_AFTER_E": "1"])
    expect(!res1.ok, "Apply fails when token persist fails")
    expectEqual(res1.status, 6, "Apply returns exit code 6 on save failure")
    expect(res1.stderr.contains("FAIL_SAVE"), "Outputs FAIL_SAVE")
    expect(res1.stderr.contains("ROLLBACK_SUCCESS"), "Outputs ROLLBACK_SUCCESS when compensating release succeeds")
    expectEqual(harness.xCount(), 1, "Compensating pfctl -X was invoked")

    // Restore permissions and clean lock for subtest 2
    _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: harness.stateDir.path)
    let lockDir = harness.stateDir.appendingPathComponent("lock")
    try? FileManager.default.removeItem(at: lockDir)

    // Subtest 2: Save fails AND compensating release fails -> recovery token reported
    let res2 = try Shell.sh(applyScript, environment: ["FAKE_CHMOD_READONLY_AFTER_E": "1", "FAKE_FAIL_X": "1"])
    expect(!res2.ok, "Apply fails when save fails and X fails")
    expectEqual(res2.status, 6, "Apply returns exit code 6 on save failure with failed rollback")
    expect(res2.stderr.contains("ROLLBACK_FAILED"), "Outputs ROLLBACK_FAILED")
    expect(res2.stderr.contains("sudo pfctl -X"), "Outputs explicit manual recovery command with token")
} catch {
    expect(false, "Save failure rollback test failed: \(error)")
}

// 2.6 Fail-closed: empty active ruleset or missing anchor acquires zero tokens
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )

    let resEmpty = try Shell.sh(applyScript, environment: ["FAKE_EMPTY_RULES": "1"])
    expect(!resEmpty.ok, "Empty active ruleset fails closed")
    expectEqual(resEmpty.status, 3, "Returns exit code 3 on empty ruleset")
    expectEqual(harness.eCount(), 0, "No token acquired on empty ruleset")

    let resMissing = try Shell.sh(applyScript, environment: ["FAKE_MISSING_ANCHOR": "1"])
    expect(!resMissing.ok, "Missing anchor fails closed")
    expectEqual(resMissing.status, 3, "Returns exit code 3 on missing anchor")
    expectEqual(harness.eCount(), 0, "No token acquired when anchor is missing")
} catch {
    expect(false, "Fail-closed reachability test failed: \(error)")
}

// 2.7 Symlink rejection: symlink stateDir and symlink tokenFile fail closed
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    // Symlink state directory
    let symlinkState = harness.baseDir.appendingPathComponent("symlink-state")
    try FileManager.default.createSymbolicLink(at: symlinkState, withDestinationURL: harness.stateDir)

    let scriptSymlinkDir = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: symlinkState.path,
        pfctl: harness.pfctlPath
    )
    let resSymlinkDir = try Shell.sh(scriptSymlinkDir)
    expect(!resSymlinkDir.ok, "Symlink state directory rejected")
    expectEqual(resSymlinkDir.status, 8, "Returns exit code 8 on symlink state directory")
    expect(resSymlinkDir.stderr.contains("FAIL_SYMLINK"), "Outputs FAIL_SYMLINK")

    // Symlink token file
    let tokenTarget = harness.baseDir.appendingPathComponent("token-target.txt")
    try "99999999".write(to: tokenTarget, atomically: true, encoding: .utf8)
    let tokenFile = harness.stateDir.appendingPathComponent("pf-token")
    try FileManager.default.createSymbolicLink(at: tokenFile, withDestinationURL: tokenTarget)

    let scriptSymlinkFile = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let resSymlinkFile = try Shell.sh(scriptSymlinkFile)
    expect(!resSymlinkFile.ok, "Symlink token file rejected")
    expectEqual(resSymlinkFile.status, 8, "Returns exit code 8 on symlink token file")
} catch {
    expect(false, "Symlink rejection test failed: \(error)")
}

// 2.8 Stale token rejection via pfctl -s References: empty refs, suffix collision, non-numeric
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )

    // Case A: Token in file is not present in References (other token)
    let tokenFile = harness.stateDir.appendingPathComponent("pf-token")
    try "77777777".write(to: tokenFile, atomically: true, encoding: .utf8)
    let resStale = try Shell.sh(applyScript, environment: ["FAKE_STALE_REFS": "1"])
    expect(!resStale.ok, "Stale token not matching active references fails closed")
    expectEqual(resStale.status, 4, "Returns exit code 4 on stale token")
    expect(resStale.stderr.contains("FAIL_STALE"), "Outputs FAIL_STALE")

    // Case B: References command returns empty output even though PF is Enabled -> NO FALLBACK to enabled!
    try "77777777".write(to: tokenFile, atomically: true, encoding: .utf8)
    let resEmpty = try Shell.sh(applyScript, environment: ["FAKE_EMPTY_REFS": "1"])
    expect(!resEmpty.ok, "Empty references fails closed without fallback to Status: Enabled")
    expectEqual(resEmpty.status, 4, "Returns exit code 4 on empty references")
    expect(resEmpty.stderr.contains("FAIL_STALE"), "Outputs FAIL_STALE when References unavailable")

    // Case C: Suffix collision (token in file is '9988', but References has '19988')
    try "9988".write(to: tokenFile, atomically: true, encoding: .utf8)
    let resSuffix = try Shell.sh(applyScript, environment: ["FAKE_SUFFIX_REFS": "1"])
    expect(!resSuffix.ok, "Suffix collision on token ID fails closed")
    expectEqual(resSuffix.status, 4, "Returns exit code 4 on suffix collision")
    expect(resSuffix.stderr.contains("FAIL_STALE"), "Outputs FAIL_STALE on suffix collision")

    // Case D: Non-numeric token in file
    try "abc-token".write(to: tokenFile, atomically: true, encoding: .utf8)
    let resNonNumeric = try Shell.sh(applyScript)
    expect(!resNonNumeric.ok, "Non-numeric token in file fails closed")
    expectEqual(resNonNumeric.status, 4, "Returns exit code 4 on non-numeric token")
    expect(resNonNumeric.stderr.contains("FAIL_STALE"), "Outputs FAIL_STALE on non-numeric token")
} catch {
    expect(false, "Stale token test failed: \(error)")
}

// 2.10 Rule load failure: new token rolled back; reused token preserves old working rules
do {
    let harness = try FakePfctlHarness()
    defer { harness.cleanup() }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )

    // Case A: Rule load fails on newly acquired token -> compensating release and token file removed
    let resA = try Shell.sh(applyScript, environment: ["FAKE_FAIL_LOAD": "1"])
    expect(!resA.ok, "Rule load failure exits non-zero")
    expectEqual(resA.status, 7, "Returns exit code 7 on rule load failure")
    expect(resA.stderr.contains("ROLLBACK_SUCCESS"), "Outputs ROLLBACK_SUCCESS on new token rule load failure")
    expectEqual(harness.xCount(), 1, "Newly acquired token released")
    let tokenFile = harness.stateDir.appendingPathComponent("pf-token")
    expect(!FileManager.default.fileExists(atPath: tokenFile.path), "Token file removed after successful rollback")

    // Case B: Reused token rule load failure -> working old rules are NOT flushed and token preserved
    // First, successful apply to get an active token
    _ = try Shell.sh(applyScript)
    expect(FileManager.default.fileExists(atPath: tokenFile.path), "Token file active before second apply")
    let xBefore = harness.xCount()

    // Second apply with FAKE_FAIL_LOAD=1
    let resB = try Shell.sh(applyScript, environment: ["FAKE_FAIL_LOAD": "1"])
    expect(!resB.ok, "Second apply fails on rule load error")
    expectEqual(resB.status, 7, "Returns exit code 7 on reused token rule load failure")
    expectEqual(harness.xCount(), xBefore, "Reused token is NOT released on rule load error")
    expect(FileManager.default.fileExists(atPath: tokenFile.path), "Working token file preserved on reused load failure")
} catch {
    expect(false, "Rule load failure test failed: \(error)")
}

// 2.11 Disable cleanup failure when token file cannot be deleted
do {
    let harness = try FakePfctlHarness()
    defer {
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: harness.stateDir.path)
        harness.cleanup()
    }

    let dummyRules = harness.baseDir.appendingPathComponent("rules.conf")
    try "pass quick on lo0 all\n".write(to: dummyRules, atomically: true, encoding: .utf8)

    let applyScript = KillSwitch.makeApplyScript(
        rulesFile: dummyRules.path,
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    _ = try Shell.sh(applyScript)

    let disableScript = KillSwitch.makeDisableScript(
        anchor: KillSwitch.anchorName,
        stateDir: harness.stateDir.path,
        pfctl: harness.pfctlPath
    )
    let res = try Shell.sh(disableScript, environment: ["FAKE_CHMOD_READONLY_DURING_X": "1"])
    expect(!res.ok, "Disable fails when token cleanup fails")
    expectEqual(res.status, 6, "Returns exit code 6 on cleanup failure")
    expect(res.stderr.contains("FAIL_CLEANUP"), "Outputs FAIL_CLEANUP")
} catch {
    expect(false, "Disable cleanup failure test failed: \(error)")
}

// MARK: - 3. DNSZones Validation, Ownership & Staging

// Empty nameservers in enabled zone rejected
do {
    let emptyZone = DNSZone(zone: "empty.corp.example.com", nameservers: [], enabled: true)
    do {
        _ = try DNSZones.apply([emptyZone])
        expect(false, "Enabled zone with empty nameservers must be rejected")
    } catch DNSZoneError.emptyNameservers {
        expect(true, "Empty nameservers in enabled zone caught")
    } catch {
        expect(false, "Unexpected error for empty nameservers: \(error)")
    }
}

// Nameserver with whitespace/newline rejected
expect(!DNSZones.isValidNameserver("198.51.100.1\n"), "Nameserver with newline rejected")
expect(!DNSZones.isValidNameserver("198.51.100.1 203.0.113.1"), "Nameserver with space rejected")
expect(!DNSZones.isValidNameserver("198.51.100.1\t"), "Nameserver with tab rejected")

// DNS Production Script Builder Tests: symlinks, unowned files, cp failure, and lifecycle
do {
    let tempResolverDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("dns-script-test-\(UUID().uuidString)", isDirectory: true)
    let tempStagingDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("dns-staged-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempResolverDir, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: tempStagingDir, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: tempResolverDir)
        try? FileManager.default.removeItem(at: tempStagingDir)
    }

    // 3.1 Symlink target rejection in makeApplyScript
    let symlinkTarget = tempResolverDir.appendingPathComponent("real.target")
    try "nameserver 198.51.100.1\n".write(to: symlinkTarget, atomically: true, encoding: .utf8)
    let symlinkFile = tempResolverDir.appendingPathComponent("symlink.zone")
    try FileManager.default.createSymbolicLink(at: symlinkFile, withDestinationURL: symlinkTarget)

    let stagedFile = tempStagingDir.appendingPathComponent("symlink.zone")
    try "# Generated by RouteClue — do not edit\nnameserver 198.51.100.2\n".write(to: stagedFile, atomically: true, encoding: .utf8)

    let entrySymlink = DNSZones.StagedEntry(zone: "symlink.zone", stagedPath: stagedFile.path, enabled: true)
    let scriptSymlink = DNSZones.makeApplyScript(stagedEntries: [entrySymlink], targetDirectory: tempResolverDir.path, flushCache: false)
    let resSymlink = try Shell.sh(scriptSymlink)
    expect(!resSymlink.ok, "Apply script rejects symlink target")
    expectEqual(resSymlink.status, 4, "Returns exit code 4 on symlink")
    expect(resSymlink.stderr.contains("FAIL_SYMLINK"), "Outputs FAIL_SYMLINK")

    // 3.2 Unowned file protection
    let unownedFile = tempResolverDir.appendingPathComponent("unowned.zone")
    try "# Corporate custom DNS config\nnameserver 198.51.100.1\n".write(to: unownedFile, atomically: true, encoding: .utf8)
    let stagedUnowned = tempStagingDir.appendingPathComponent("unowned.zone")
    try "# Generated by RouteClue — do not edit\nnameserver 198.51.100.2\n".write(to: stagedUnowned, atomically: true, encoding: .utf8)

    let entryUnowned = DNSZones.StagedEntry(zone: "unowned.zone", stagedPath: stagedUnowned.path, enabled: true)
    let scriptUnowned = DNSZones.makeApplyScript(stagedEntries: [entryUnowned], targetDirectory: tempResolverDir.path, flushCache: false)
    let resUnowned = try Shell.sh(scriptUnowned)
    expect(!resUnowned.ok, "Apply script rejects unowned file overwrite")
    expectEqual(resUnowned.status, 5, "Returns exit code 5 on unowned file")
    let unownedContent = try String(contentsOf: unownedFile, encoding: .utf8)
    expect(unownedContent.contains("Corporate custom DNS"), "Unowned file content is preserved")

    // 3.3 cp failure halts before flush
    let entryMissingSource = DNSZones.StagedEntry(zone: "missing.zone", stagedPath: "/nonexistent/path/file", enabled: true)
    let scriptMissing = DNSZones.makeApplyScript(stagedEntries: [entryMissingSource], targetDirectory: tempResolverDir.path, flushCache: true)
    let resMissing = try Shell.sh(scriptMissing)
    expect(!resMissing.ok, "Script halts on cp error under set -e")

    // 3.4 Normal apply and remove
    let validStaged = tempStagingDir.appendingPathComponent("valid.zone")
    try "# Generated by RouteClue — do not edit\nnameserver 198.51.100.10\n".write(to: validStaged, atomically: true, encoding: .utf8)
    let entryValid = DNSZones.StagedEntry(zone: "valid.zone", stagedPath: validStaged.path, enabled: true)
    let scriptValid = DNSZones.makeApplyScript(stagedEntries: [entryValid], targetDirectory: tempResolverDir.path, flushCache: false)
    let resValid = try Shell.sh(scriptValid)
    expect(resValid.ok, "Valid apply script succeeds")
    let appliedFile = tempResolverDir.appendingPathComponent("valid.zone")
    expect(FileManager.default.fileExists(atPath: appliedFile.path), "Target resolver file created")

    let removeScript = DNSZones.makeRemoveScript(zone: "valid.zone", targetDirectory: tempResolverDir.path, flushCache: false)
    let resRemove = try Shell.sh(removeScript)
    expect(resRemove.ok, "Remove script succeeds for owned zone")
    expect(!FileManager.default.fileExists(atPath: appliedFile.path), "Target resolver file removed")

    let removeUnownedScript = DNSZones.makeRemoveScript(zone: "unowned.zone", targetDirectory: tempResolverDir.path, flushCache: false)
    let resRemoveUnowned = try Shell.sh(removeUnownedScript)
    expect(!resRemoveUnowned.ok, "Remove script rejects deleting unowned zone")
    expectEqual(resRemoveUnowned.status, 5, "Returns exit code 5 on unowned deletion attempt")
    expect(FileManager.default.fileExists(atPath: unownedFile.path), "Unowned file preserved after failed remove")
} catch {
    expect(false, "DNS script test failed: \(error)")
}

// MARK: - 4. BSD Netstat & Route Parsing

expect(RouteManager.parseIPv4("10.20.0.1") == 0x0A140001, "parseIPv4 valid")
expect(RouteManager.parseIPv4("10.20.0.foo") == nil, "parseIPv4 rejected non-digit")
expect(RouteManager.parseIPv4("10.20.0.256") == nil, "parseIPv4 rejected overflow")

expect(RouteManager.isValidSubnet("10.0.0.0/8"), "valid cidr subnet")
expect(!RouteManager.isValidSubnet("10.0.0.0/33"), "invalid mask subnet")
expect(!RouteManager.isValidSubnet("10.256.0.0/16"), "invalid octet subnet")

// Short CIDRs and BSD Netstat destinations
expectEqual(RouteManager.parseNetstatDestination("default")?.network, 0, "netstat default parsed")
expectEqual(RouteManager.parseNetstatDestination("10")?.prefix, 8, "netstat class A parsed")
expectEqual(RouteManager.parseNetstatDestination("169.254")?.prefix, 16, "netstat class B parsed")
expectEqual(RouteManager.parseNetstatDestination("192.168.1")?.prefix, 24, "netstat class C parsed")
expectEqual(RouteManager.parseNetstatDestination("10.53/16")?.prefix, 16, "netstat cidr 10.53/16 parsed")
expectEqual(RouteManager.parseNetstatDestination("2/7")?.prefix, 7, "netstat 2/7 parsed")
expectEqual(RouteManager.parseNetstatDestination("4/6")?.prefix, 6, "netstat 4/6 parsed")
expectEqual(RouteManager.parseNetstatDestination("8/5")?.prefix, 5, "netstat 8/5 parsed")
expectEqual(RouteManager.parseNetstatDestination("128.0/1")?.prefix, 1, "netstat 128.0/1 parsed")

// Scoped %interface destination parsing
expectEqual(RouteManager.parseNetstatDestination("default%en0")?.network, 0, "netstat scoped default%en0 parsed")
expectEqual(RouteManager.parseNetstatDestination("10.0.0.0/8%en0")?.prefix, 8, "netstat scoped 10.0.0.0/8%en0 parsed")

// Netstat table rows fixture with Expire column
let netstatFixture = """
Destination        Gateway            Flags               Netif Expire
default            169.254.10.1       UGScg             utun225
default            192.168.1.1        UGScIg                en0
10.53/16           172.17.4.1         UGScI                 en0
169.254            link#11            UCS                   en0      !
"""
let rows = RouteManager.parseNetstatRows(netstatFixture)
expectEqual(rows.count, 4, "4 rows parsed from netstat fixture")
expect(rows[1].isScoped, "row 1 is scoped (flag I)")
expect(rows[3].isLinkLayer, "row 3 is link layer (link#11)")
expectEqual(rows[3].expire, "!", "row 3 expire flag parsed")

// Route health checks
let okStatus = RouteStatus(
    subnet: "10.53.0.0/16",
    gateway: "172.17.4.1",
    interface: "en0",
    ifScoped: true,
    expectedGateway: "172.17.4.1",
    expectedInterface: "en0"
)
expect(okStatus.isOK, "matching expected gateway and interface is OK")

let wrongGwStatus = RouteStatus(
    subnet: "10.53.0.0/16",
    gateway: "172.17.4.99",
    interface: "en0",
    ifScoped: true,
    expectedGateway: "172.17.4.1",
    expectedInterface: "en0"
)
expect(!wrongGwStatus.isOK, "mismatched expected gateway is NOT OK")

// MARK: - 5. Path Explainer

let tunnelPath = IPPath(
    address: "203.0.113.5",
    interface: "utun3",
    gateway: "10.255.0.1",
    ifScoped: false,
    interfaceAddress: "10.255.0.2",
    warning: nil
)
let tunnelExplanation = PathExplanation(
    host: "external.com",
    resolverDomain: nil,
    resolverServers: ["1.1.1.1"],
    addresses: ["203.0.113.5"],
    dnsError: nil,
    paths: [tunnelPath],
    killSwitchEnabled: true,
    tunnelUp: true,
    verdict: .viaTunnel,
    notes: []
)
expectEqual(tunnelExplanation.verdict, .viaTunnel, "traffic through tunnel interface is viaTunnel, not blocked")

// IPv6 nameserver preservation (no truncation at colon)
let colonLine = "nameserver[0] : 2001:4860:4860::8888"
var parsedIPv6Server = ""
if let colonIndex = colonLine.firstIndex(of: ":") {
    parsedIPv6Server = String(colonLine[colonLine.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces))
}
expectEqual(parsedIPv6Server, "2001:4860:4860::8888", "IPv6 nameserver preserved with all colons")

// MARK: - 6. Pure Offline PolicyVerifier & SnapshotDiff (Zero Network Dependency)

let offlineReport = DiagnosticReport(
    lanInterface: "en0",
    lanAddress: "192.168.1.104",
    gateway: "192.168.1.1",
    tunnelInterface: "utun3",
    tunnelUp: true,
    defaultInterface: "utun3",
    resolvers: ["1.1.1.1"],
    routes: [
        RouteStatus(subnet: "10.0.0.0/8", gateway: "192.168.1.1", interface: "en0", ifScoped: true),
        RouteStatus(subnet: "10.0.0.0/8", gateway: "192.168.1.1", interface: "en0", ifScoped: true), // Duplicate
    ],
    zones: [],
    exitIP: "203.0.113.1",
    notes: []
)

// SnapshotDiff duplicate safety
let snapA = NetworkSnapshot(report: offlineReport, killSwitchActive: true)
let snapB = NetworkSnapshot(report: offlineReport, killSwitchActive: true)
let safeDiff = SnapshotDiff(before: snapA, after: snapB)
expect(!safeDiff.hasDrift, "SnapshotDiff handles duplicate routes without crash")

// PolicyVerifier offline evaluation with injected observations
let polA = RouteCluePolicy(requireTunnelUp: true, requiredSubnets: ["10.0.0.0/8"])
let verReportA = PolicyVerifier.verify(
    policy: polA,
    config: sampleConfig(),
    snapshot: offlineReport,
    killSwitchState: true,
    routeStatuses: [RouteStatus(subnet: "10.0.0.0/8", gateway: "192.168.1.1", interface: "en0", ifScoped: true)]
)
expect(verReportA.allPassed, "Offline policy verification passed with injected observations")

// PolicyVerifier: unknown kill switch state is NOT pass
let polKS = RouteCluePolicy(requireKillSwitch: true)
let verReportKS = PolicyVerifier.verify(
    policy: polKS,
    config: sampleConfig(),
    snapshot: offlineReport,
    killSwitchState: nil // explicitly unknown
)
let ksCheck = verReportKS.checks.first { $0.name == "Kill switch state" }
expect(ksCheck?.passed == false, "Unknown kill switch state is explicitly rejected (not pass)")

// PolicyVerifier: requiredZone exists-but-no-servers case must FAIL
let polZone = RouteCluePolicy(requiredZones: ["empty.corp.com"])
let verReportZoneEmpty = PolicyVerifier.verify(
    policy: polZone,
    config: sampleConfig(),
    snapshot: offlineReport,
    installedZones: ["empty.corp.com"],
    resolverTable: [ResolverInfo(domain: "empty.corp.com", servers: [])], // zero servers!
    dnsProbe: { _, _ in false }
)
let zoneCheckEmpty = verReportZoneEmpty.checks.first { $0.name == "Zone empty.corp.com" }
expect(zoneCheckEmpty?.passed == false, "Zone with zero servers fails verification")

// PolicyVerifier: requiredZone missing from resolver must FAIL
let verReportZoneMissing = PolicyVerifier.verify(
    policy: polZone,
    config: sampleConfig(),
    snapshot: offlineReport,
    installedZones: ["other.corp.com"],
    resolverTable: [],
    dnsProbe: { _, _ in false }
)
let zoneCheckMissing = verReportZoneMissing.checks.first { $0.name == "Zone empty.corp.com" }
expect(zoneCheckMissing?.passed == false, "Missing zone fails verification")

// PolicyVerifier: requiredZone with servers that answer PASSES
let verReportZoneOK = PolicyVerifier.verify(
    policy: polZone,
    config: sampleConfig(),
    snapshot: offlineReport,
    installedZones: ["empty.corp.com"],
    resolverTable: [ResolverInfo(domain: "empty.corp.com", servers: ["10.0.0.10"])],
    dnsProbe: { _, _ in true }
)
let zoneCheckOK = verReportZoneOK.checks.first { $0.name == "Zone empty.corp.com" }
expect(zoneCheckOK?.passed == true, "Zone with responsive servers passes verification")

// PolicyVerifier: expected config has servers, but actual resolver observation has empty servers -> must FAIL!
var configWithZone = sampleConfig()
configWithZone.dnsZones = [DNSZone(zone: "corp.example.com", nameservers: ["10.0.0.10", "10.0.0.11"], enabled: true)]
let polZoneConfig = RouteCluePolicy(requiredZones: ["corp.example.com"])
let verReportConfigFallback = PolicyVerifier.verify(
    policy: polZoneConfig,
    config: configWithZone,
    snapshot: offlineReport,
    installedZones: ["corp.example.com"],
    resolverTable: [ResolverInfo(domain: "corp.example.com", servers: [])], // actual resolver has NO servers!
    dnsProbe: { _, _ in true }
)
let zoneCheckFallback = verReportConfigFallback.checks.first { $0.name == "Zone corp.example.com" }
expect(zoneCheckFallback?.passed == false, "Must NOT fallback to expected config nameservers when actual resolver has none — fails verification")

// PolicyVerifier: hostsBlocked returns false because runtime packet drop is unverified
let polBlocked = RouteCluePolicy(hostsBlocked: ["blocked.corp.example.com"])
let verReportBlocked = PolicyVerifier.verify(
    policy: polBlocked,
    config: sampleConfig(),
    snapshot: offlineReport
)
let blockedCheck = verReportBlocked.checks.first { $0.name == "Blocked host blocked.corp.example.com" }
expect(blockedCheck?.passed == false, "hostsBlocked is marked passed: false because actual kernel drop is unverified")
expect(blockedCheck?.detail.contains("Фактическая блокировка ядром PF не проверена") == true, "hostsBlocked reports honest unverified drop detail")

// MARK: - 7. ConfigStore Immutable & Injectable Tests (Temp Directory)

do {
    let tempBase = FileManager.default.temporaryDirectory.appendingPathComponent("rc-store-\(UUID().uuidString)", isDirectory: true)
    let rcDir = tempBase.appendingPathComponent("RouteClue")
    let tgDir = tempBase.appendingPathComponent("TunnelGuard")
    try FileManager.default.createDirectory(at: tempBase, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempBase) }

    let store = ConfigStore(directory: rcDir, legacyDirectory: tgDir)

    // Test A: Clean dir -> default config
    let freshConfig = try store.load()
    expect(freshConfig.corpSubnets.isEmpty, "Fresh load returns default empty config")

    // Test B: Read-only fallback to legacy TunnelGuard config
    try FileManager.default.createDirectory(at: tgDir, withIntermediateDirectories: true)
    let legacyConfig = RouteClueConfig(corpSubnets: ["172.16.0.0/12"], lanInterfaces: ["en0"])
    let legacyData = try JSONEncoder().encode(legacyConfig)
    try legacyData.write(to: store.legacyFileURL)

    let fallbackLoaded = try store.load()
    expectEqual(fallbackLoaded.corpSubnets, ["172.16.0.0/12"], "Fallback loads legacy TunnelGuard config")

    // Test C: Explicit save writes to RouteClue directory and leaves TunnelGuard untouched
    var modified = fallbackLoaded
    modified.corpSubnets.append("10.50.0.0/16")
    try store.save(modified)

    expect(FileManager.default.fileExists(atPath: store.fileURL.path), "Saved to RouteClue config.json")
    let reloadedNew = try store.load()
    expectEqual(reloadedNew.corpSubnets, ["172.16.0.0/12", "10.50.0.0/16"], "Reloaded new RouteClue config")

    // Verify legacy file was NOT overwritten
    let legacyRaw = try Data(contentsOf: store.legacyFileURL)
    let legacyReloaded = try JSONDecoder().decode(RouteClueConfig.self, from: legacyRaw)
    expectEqual(legacyReloaded.corpSubnets, ["172.16.0.0/12"], "Legacy TunnelGuard config was preserved unchanged")

    // Test D: Corrupted JSON in RouteClue config throws ConfigError.corrupted
    try "{ bad-json: true ".write(to: store.fileURL, atomically: true, encoding: .utf8)
    do {
        _ = try store.load()
        expect(false, "Corrupted RouteClue config must throw ConfigError.corrupted")
    } catch ConfigError.corrupted {
        expect(true, "Corrupted RouteClue config throws ConfigError.corrupted")
    } catch {
        expect(false, "Unexpected error type for corrupted config: \(error)")
    }

    // Test E: Corrupted JSON in legacy config throws ConfigError.corrupted
    try FileManager.default.removeItem(at: store.fileURL)
    try "{ bad-legacy-json: true ".write(to: store.legacyFileURL, atomically: true, encoding: .utf8)
    do {
        _ = try store.load()
        expect(false, "Corrupted legacy config must throw ConfigError.corrupted")
    } catch ConfigError.corrupted {
        expect(true, "Corrupted legacy config throws ConfigError.corrupted")
    } catch {
        expect(false, "Unexpected error type for corrupted legacy config: \(error)")
    }
} catch {
    expect(false, "ConfigStore temp directory test failed: \(error)")
}

// MARK: - Final Result

if failures == 0 {
    print("Self test passed: \(checks) checks")
    exit(0)
} else {
    print("Self test failed: \(failures) of \(checks) checks")
    exit(1)
}
