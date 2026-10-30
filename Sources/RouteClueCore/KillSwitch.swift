import Foundation

public struct KillSwitchPlan: Sendable, Equatable {
    public let rules: String
    public let interfaces: [String]
    public let warnings: [String]

    public init(rules: String, interfaces: [String], warnings: [String] = []) {
        self.rules = rules
        self.interfaces = interfaces
        self.warnings = warnings
    }
}

public enum KillSwitchError: Error, CustomStringConvertible, Sendable, Equatable {
    case invalidInterface(String)
    case invalidIPOrCIDR(String)
    case allowListFileNotFound(String)
    case allowListInvalidLine(line: Int, content: String)
    case validationFailed(String)
    case anchorNotReachable(String)
    case executionFailed(String)

    public var description: String {
        switch self {
        case let .invalidInterface(iface):
            return "Недопустимое имя сетевого интерфейса: '\(iface)'"
        case let .invalidIPOrCIDR(val):
            return "Некорректный IP или CIDR: '\(val)'"
        case let .allowListFileNotFound(path):
            return "Файл allow-list не найден: '\(path)'"
        case let .allowListInvalidLine(line, content):
            return "Некорректная запись в файле allow-list (строка \(line)): '\(content)'"
        case let .validationFailed(reason):
            return "Синтаксическая проверка PF правил завершилась ошибкой: \(reason)"
        case let .anchorNotReachable(reason):
            return "Анкер PF недостижим в активном ruleset ядра: \(reason)"
        case let .executionFailed(msg):
            return "Ошибка управления PF: \(msg)"
        }
    }
}

/// A pf-based kill switch for macOS using isolated anchors.
///
/// Rules are applied inside the `com.apple/routeclue` anchor so they never flush
/// or overwrite the global macOS ruleset or rules from other software (Docker, LuLu, etc.).
public enum KillSwitch {
    public static let anchorName = "com.apple/routeclue"
    public static let legacyAnchorName = "com.apple/routeclue.legacy"

    public static let defaultStateDir = "/var/run/routeclue"
    public static let defaultPfctlPath = "/sbin/pfctl"

    public static let disclosures = [
        "Root bypass: процессы с UID 0 (root) обходят kill switch для обеспечения работы VPN-демона.",
        "Existing states: сетевые соединения, установленные до включения kill switch, продолжают существовать до истечения их PF state.",
        "IPv6 limits: весь IPv6-трафик блокируется на физических интерфейсах (кроме ICMPv6 ND и root), но маршруты IPv6 утилитой не настраиваются.",
    ]

    public static var tokenFileURL: URL {
        URL(fileURLWithPath: "\(defaultStateDir)/pf-token")
    }

    public static var legacyTokenFileURL: URL {
        ConfigStore.legacyDirectory.appendingPathComponent("pf-token")
    }

    /// Читает токен из защищенного state-каталога (если доступен для чтения).
    public static func savedToken(stateDir: String = defaultStateDir) -> String? {
        let url = URL(fileURLWithPath: "\(stateDir)/pf-token")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Возвращает токен старой конфигурации (только для legacy recovery).
    public static func legacySavedToken() -> String? {
        guard let text = try? String(contentsOf: legacyTokenFileURL, encoding: .utf8) else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    public static func saveToken(_ token: String, stateDir: String = defaultStateDir) throws {
        let dirURL = URL(fileURLWithPath: stateDir)
        try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        let tokenURL = dirURL.appendingPathComponent("pf-token")
        try token.write(to: tokenURL, atomically: true, encoding: .utf8)
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)
    }

    public static func clearToken(stateDir: String = defaultStateDir) {
        let tokenURL = URL(fileURLWithPath: "\(stateDir)/pf-token")
        try? FileManager.default.removeItem(at: tokenURL)
    }

    public static func clearLegacyToken() {
        try? FileManager.default.removeItem(at: legacyTokenFileURL)
    }

    public static func isValidInterfaceName(_ iface: String) -> Bool {
        guard !iface.isEmpty, iface.count <= 16 else { return false }
        let pattern = "^[a-zA-Z0-9_]+$"
        return iface.range(of: pattern, options: .regularExpression) != nil
    }

    public static func physicalInterfaces() -> [String] {
        let result = try? Shell.run("/sbin/ifconfig", ["-l"])
        return (result?.stdout ?? "")
            .split(separator: " ")
            .map(String.init)
            .filter { $0.hasPrefix("en") && Int($0.dropFirst(2)) != nil && isValidInterfaceName($0) }
    }

    /// Проверяет, достижим ли анкер из переданного текста active ruleset (pfctl -sr).
    /// Разрешены ТОЛЬКО доказанные вызовы: 'anchor "com.apple/*"' или 'anchor "com.apple/routeclue"'.
    /// Bare 'com.apple', bare rootless, комментарии и обусловленные вызовы строго отклоняются.
    public static func isAnchorReachable(inRuleset ruleset: String) -> (reachable: Bool, reason: String) {
        let trimmed = ruleset.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return (false, "Активный ruleset пуст. Анкерные правила не будут обрабатываться ядром.")
        }

        let lines = trimmed.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        // Строгий шаблон: ТОЛЬКО com.apple/* или com.apple/routeclue (без bare com.apple)
        let validPattern = "^anchor \"(com\\.apple/\\*|com\\.apple/routeclue)\"( all)?$"

        let hasAnchor = lines.contains { line in
            if line.hasPrefix("#") { return false }
            return line.range(of: validPattern, options: .regularExpression) != nil
        }

        if !hasAnchor {
            return (false, "В активном ruleset ядра отсутствует вызов 'anchor \"com.apple/*\"' или точный 'anchor \"\(anchorName)\"'. Пакеты не будут направляться в правила RouteClue.")
        }
        return (true, "Анкер достижим из активного ruleset.")
    }

    /// Обнаруживает, активен ли старый legacy anchor.
    public static func isLegacyAnchorActive() -> Bool {
        guard let result = try? Shell.run("/sbin/pfctl", ["-a", legacyAnchorName, "-s", "rules"]), result.ok else {
            return false
        }
        return !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// System anchors must be preserved when generating standalone root rulesets in diagnostics.
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

    /// Формирует план правил PF. Валидирует интерфейсы, allowNets, extraAllow, dnsAllow и allowList.
    public static func plan(
        config: RouteClueConfig,
        interfaces: [String]? = nil,
        anchors: [String]? = nil
    ) throws -> KillSwitchPlan {
        let candidateIfaces = interfaces ?? physicalInterfaces()
        guard !candidateIfaces.isEmpty else {
            throw KillSwitchError.invalidInterface("Не найдено подходящих физических интерфейсов (en*).")
        }

        for iface in candidateIfaces {
            guard isValidInterfaceName(iface) else {
                throw KillSwitchError.invalidInterface(iface)
            }
        }
        let ifaces = candidateIfaces

        // Валидация allowNets
        for net in config.killSwitch.allowNets {
            guard RouteManager.isValidSubnet(net) else {
                throw KillSwitchError.invalidIPOrCIDR("allowNets: '\(net)'")
            }
        }

        // Валидация extraAllow
        for entry in config.killSwitch.extraAllow {
            guard RouteManager.isValidSubnet(entry) || RouteManager.parseIPv4(entry) != nil else {
                throw KillSwitchError.invalidIPOrCIDR("extraAllow: '\(entry)'")
            }
        }

        // Валидация dnsAllow
        for dns in config.killSwitch.dnsAllow {
            guard RouteManager.parseIPv4(dns) != nil else {
                throw KillSwitchError.invalidIPOrCIDR("dnsAllow: '\(dns)'")
            }
        }

        // Чтение и инлайнинг allowListPath как данных (без интерполяции пути в PF директиву file)
        var allowListEntries: [String] = []
        if let path = config.killSwitch.allowListPath {
            guard FileManager.default.fileExists(atPath: path) else {
                throw KillSwitchError.allowListFileNotFound(path)
            }
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
                throw KillSwitchError.allowListFileNotFound("Не удалось прочитать \(path)")
            }
            for (idx, rawLine) in content.split(separator: "\n").enumerated() {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                guard RouteManager.isValidSubnet(trimmed) || RouteManager.parseIPv4(trimmed) != nil else {
                    throw KillSwitchError.allowListInvalidLine(line: idx + 1, content: trimmed)
                }
                allowListEntries.append(trimmed)
            }
        }

        var lines: [String] = []
        if let anchorLines = anchors {
            lines.append("set skip on lo0")
            lines.append(contentsOf: anchorLines)
            lines.append("")
        } else {
            lines.append("pass quick on lo0 all")
            lines.append("")
        }

        if !allowListEntries.isEmpty {
            lines.append("table <allowlist> { \(allowListEntries.joined(separator: ", ")) }")
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
            // IPv6 Neighbor Discovery (ICMPv6) prevents Happy Eyeballs connection stalls.
            lines.append("pass out quick on \(iface) proto ipv6-icmp to { ff02::/16, fe80::/10 } keep state")

            if !config.killSwitch.allowNets.isEmpty {
                lines.append("pass out quick on \(iface) inet to { \(config.killSwitch.allowNets.joined(separator: ", ")) } keep state")
            }
            if !allowListEntries.isEmpty {
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

        return KillSwitchPlan(rules: lines.joined(separator: "\n"), interfaces: ifaces, warnings: [])
    }

    /// Validates the ruleset with pfctl dry-run. Fails closed on any non-zero exit code or execution error.
    public static func validate(_ plan: KillSwitchPlan) -> String {
        guard !plan.rules.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return "Сгенерированный набор правил PF пуст."
        }
        do {
            let result = try Shell.run("/sbin/pfctl", ["-n", "-a", anchorName, "-f", "-"], input: plan.rules)
            let noise = ["Use of -f option", "present in the main ruleset", "See /etc/pf.conf"]
            let filtered = result.combined
                .split(separator: "\n")
                .map(String.init)
                .filter { line in !line.isEmpty && !noise.contains { line.contains($0) } }
                .joined(separator: "\n")

            if !result.ok {
                return filtered.isEmpty ? "pfctl завершился с кодом ошибки \(result.status)" : filtered
            }
            return filtered
        } catch {
            return "Ошибка выполнения pfctl: \(error)"
        }
    }

    /// Генерирует полностью автономный bash-скрипт для применения правил под единой блокировкой.
    /// Все операции (проверка reachability, проверка существующего токена, получение нового -E 2>&1,
    /// атомарное сохранение токена с правами 0600, загрузка правил в анкер и компенсирующий откат)
    /// выполняются внутри одного сеанса под защитой $STATE_DIR/lock.
    public static func makeApplyScript(
        rulesFile: String,
        anchor: String = anchorName,
        stateDir: String = defaultStateDir,
        pfctl: String = defaultPfctlPath
    ) -> String {
        let qRulesFile = Shell.quote(rulesFile)
        let qAnchor = Shell.quote(anchor)
        let qStateDir = Shell.quote(stateDir)
        let qPfctl = Shell.quote(pfctl)

        return """
        set -e
        STATE_DIR=\(qStateDir)
        PFCTL=\(qPfctl)
        ANCHOR=\(qAnchor)
        RULES_FILE=\(qRulesFile)
        TOKEN_FILE="$STATE_DIR/pf-token"
        LOCKDIR="$STATE_DIR/lock"

        if [ -L "$STATE_DIR" ]; then
            echo "FAIL_SYMLINK: State directory $STATE_DIR is a symlink" >&2
            exit 8
        fi
        if [ -L "$TOKEN_FILE" ]; then
            echo "FAIL_SYMLINK: Token file $TOKEN_FILE is a symlink" >&2
            exit 8
        fi

        if ! mkdir -p "$STATE_DIR"; then
            echo "FAIL_DIR: Failed to create state directory $STATE_DIR" >&2
            exit 9
        fi
        DIR_UID=$(stat -f "%u" "$STATE_DIR" 2>/dev/null || true)
        CURR_UID=$(id -u)
        if [ -n "$DIR_UID" ] && [ "$DIR_UID" -ne "$CURR_UID" ]; then
            echo "FAIL_DIR: State directory $STATE_DIR is owned by UID $DIR_UID, expected current UID $CURR_UID" >&2
            exit 9
        fi
        if ! chmod 700 "$STATE_DIR"; then
            echo "FAIL_DIR: Failed to set permissions 0700 on $STATE_DIR" >&2
            exit 9
        fi

        if ! mkdir "$LOCKDIR" 2>/dev/null; then
            echo "FAIL_LOCK: PF operation already in progress" >&2
            exit 2
        fi
        trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT

        ACTIVE_RULES=$("$PFCTL" -sr 2>/dev/null || true)
        if [ -z "$ACTIVE_RULES" ]; then
            echo "FAIL_REACHABLE: Active ruleset is empty." >&2
            exit 3
        fi
        if ! echo "$ACTIVE_RULES" | grep -qE '^[[:space:]]*anchor "(com\\.apple/\\*|com\\.apple/routeclue)"([[:space:]]+all)?[[:space:]]*$'; then
            echo "FAIL_REACHABLE: Anchor com.apple/* or com.apple/routeclue not found in active ruleset." >&2
            exit 3
        fi

        REUSED_TOKEN=""
        NEW_TOKEN=""
        if [ -f "$TOKEN_FILE" ]; then
            EXISTING_TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null | tr -d '\\r\\n')
            if [ -n "$EXISTING_TOKEN" ]; then
                if ! echo "$EXISTING_TOKEN" | grep -qE '^[0-9]+$'; then
                    echo "FAIL_STALE: State token ($EXISTING_TOKEN) is not a valid numeric token." >&2
                    exit 4
                fi
                REFS=$("$PFCTL" -s References 2>/dev/null || true)
                if [ -z "$REFS" ]; then
                    echo "FAIL_STALE: Cannot verify token ($EXISTING_TOKEN): pfctl -s References is empty or unavailable." >&2
                    exit 4
                fi
                if echo "$REFS" | grep -qE "(^|[^0-9])$EXISTING_TOKEN([^0-9]|$)"; then
                    REUSED_TOKEN="$EXISTING_TOKEN"
                else
                    echo "FAIL_STALE: State token ($EXISTING_TOKEN) is not found in active pf references." >&2
                    exit 4
                fi
            fi
        fi

        if [ -z "$REUSED_TOKEN" ]; then
            ENABLE_STATUS=0
            ENABLE_OUT=$("$PFCTL" -E 2>&1) || ENABLE_STATUS=$?
            if [ "$ENABLE_STATUS" -ne 0 ]; then
                echo "FAIL_TOKEN: pfctl -E failed with code $ENABLE_STATUS: $ENABLE_OUT" >&2
                exit 5
            fi

            NEW_TOKEN=$(echo "$ENABLE_OUT" | grep "Token :" | sed 's/.*Token :[[:space:]]*//' | tr -d '\\r\\n')
            if [ -z "$NEW_TOKEN" ]; then
                echo "FAIL_TOKEN: pfctl -E did not return a reference token. Output: $ENABLE_OUT" >&2
                exit 5
            fi

            TMP_TOKEN="$STATE_DIR/pf-token.tmp.$$"
            SAVE_OK=0
            if echo "$NEW_TOKEN" > "$TMP_TOKEN" 2>/dev/null && chmod 600 "$TMP_TOKEN" 2>/dev/null && mv "$TMP_TOKEN" "$TOKEN_FILE" 2>/dev/null; then
                SAVE_OK=1
            fi

            if [ "$SAVE_OK" -ne 1 ]; then
                rm -f "$TMP_TOKEN" 2>/dev/null || true
                echo "FAIL_SAVE: Failed to persist token $NEW_TOKEN to $TOKEN_FILE" >&2
                if REL_OUT=$("$PFCTL" -X "$NEW_TOKEN" 2>&1); then
                    echo "ROLLBACK_SUCCESS: Compensating release of token $NEW_TOKEN succeeded." >&2
                else
                    echo "ROLLBACK_FAILED: Failed to release token $NEW_TOKEN: $REL_OUT. Manual recovery required: sudo pfctl -X $NEW_TOKEN" >&2
                fi
                exit 6
            fi
        fi

        if ! "$PFCTL" -a "$ANCHOR" -f "$RULES_FILE" 2>&1; then
            echo "FAIL_LOAD: Failed to load rules into anchor $ANCHOR" >&2
            if [ -n "$NEW_TOKEN" ]; then
                "$PFCTL" -a "$ANCHOR" -F rules 2>/dev/null || true
                if REL_OUT=$("$PFCTL" -X "$NEW_TOKEN" 2>&1); then
                    rm -f "$TOKEN_FILE" 2>/dev/null || true
                    echo "ROLLBACK_SUCCESS: Released newly acquired token $NEW_TOKEN after rule load failure." >&2
                else
                    echo "ROLLBACK_FAILED: Failed to release token $NEW_TOKEN: $REL_OUT. Manual recovery required: sudo pfctl -X $NEW_TOKEN" >&2
                fi
            fi
            exit 7
        fi

        if [ -n "$NEW_TOKEN" ]; then
            echo "SUCCESS: Token acquired ($NEW_TOKEN) and rules applied to $ANCHOR"
        else
            echo "SUCCESS: Existing token reused ($REUSED_TOKEN) and rules applied to $ANCHOR"
        fi
        """
    }

    /// Генерирует полностью автономный bash-скрипт для отключения правил под единой блокировкой.
    /// Очищает только правила анкера RouteClue (без -F all / -d), освобождает токен через pfctl -X
    /// и удаляет файл токена только при успешном release.
    public static func makeDisableScript(
        anchor: String = anchorName,
        stateDir: String = defaultStateDir,
        pfctl: String = defaultPfctlPath,
        legacyTokenFile: String? = nil,
        legacyAnchor: String? = legacyAnchorName
    ) -> String {
        let qAnchor = Shell.quote(anchor)
        let qStateDir = Shell.quote(stateDir)
        let qPfctl = Shell.quote(pfctl)
        let qLegacyToken = legacyTokenFile != nil ? Shell.quote(legacyTokenFile!) : "''"
        let qLegacyAnchor = legacyAnchor != nil ? Shell.quote(legacyAnchor!) : "''"

        return """
        set -e
        STATE_DIR=\(qStateDir)
        PFCTL=\(qPfctl)
        ANCHOR=\(qAnchor)
        TOKEN_FILE="$STATE_DIR/pf-token"
        LOCKDIR="$STATE_DIR/lock"
        LEGACY_TOKEN_FILE=\(qLegacyToken)
        LEGACY_ANCHOR=\(qLegacyAnchor)

        if [ -L "$STATE_DIR" ]; then
            echo "FAIL_SYMLINK: State directory $STATE_DIR is a symlink" >&2
            exit 8
        fi
        if [ -L "$TOKEN_FILE" ]; then
            echo "FAIL_SYMLINK: Token file $TOKEN_FILE is a symlink" >&2
            exit 8
        fi

        if ! mkdir -p "$STATE_DIR"; then
            echo "FAIL_DIR: Failed to create state directory $STATE_DIR" >&2
            exit 9
        fi
        DIR_UID=$(stat -f "%u" "$STATE_DIR" 2>/dev/null || true)
        CURR_UID=$(id -u)
        if [ -n "$DIR_UID" ] && [ "$DIR_UID" -ne "$CURR_UID" ]; then
            echo "FAIL_DIR: State directory $STATE_DIR is owned by UID $DIR_UID, expected current UID $CURR_UID" >&2
            exit 9
        fi
        if ! chmod 700 "$STATE_DIR"; then
            echo "FAIL_DIR: Failed to set permissions 0700 on $STATE_DIR" >&2
            exit 9
        fi

        if ! mkdir "$LOCKDIR" 2>/dev/null; then
            echo "FAIL_LOCK: PF operation already in progress" >&2
            exit 2
        fi
        trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT

        FLUSH_STATUS=0
        FLUSH_OUT=$("$PFCTL" -a "$ANCHOR" -F rules 2>&1) || FLUSH_STATUS=$?
        if [ "$FLUSH_STATUS" -ne 0 ]; then
            echo "FAIL_FLUSH: Failed to flush anchor $ANCHOR rules: $FLUSH_OUT" >&2
            exit 3
        fi

        if [ -f "$TOKEN_FILE" ]; then
            TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null | tr -d '\\r\\n')
            if [ -n "$TOKEN" ]; then
                if REL_OUT=$("$PFCTL" -X "$TOKEN" 2>&1); then
                    if ! rm -f "$TOKEN_FILE"; then
                        echo "FAIL_CLEANUP: Released token $TOKEN, but failed to remove $TOKEN_FILE" >&2
                        exit 6
                    fi
                else
                    echo "FAIL_RELEASE: Failed to release token $TOKEN: $REL_OUT" >&2
                    exit 4
                fi
            else
                rm -f "$TOKEN_FILE" 2>/dev/null || true
            fi
        fi

        LEGACY_FAILED=0
        if [ -n "$LEGACY_TOKEN_FILE" ] && [ -f "$LEGACY_TOKEN_FILE" ]; then
            LEG_TOKEN=$(cat "$LEGACY_TOKEN_FILE" 2>/dev/null | tr -d '\\r\\n')
            if [ -n "$LEG_TOKEN" ]; then
                if [ -n "$LEGACY_ANCHOR" ]; then
                    "$PFCTL" -a "$LEGACY_ANCHOR" -F rules 2>/dev/null || true
                fi
                LEG_STATUS=0
                LEG_REL=$("$PFCTL" -X "$LEG_TOKEN" 2>&1) || LEG_STATUS=$?
                if [ "$LEG_STATUS" -ne 0 ]; then
                    echo "WARN_LEGACY_RELEASE_FAILED: Failed to release legacy token $LEG_TOKEN: $LEG_REL" >&2
                    LEGACY_FAILED=1
                else
                    rm -f "$LEGACY_TOKEN_FILE" 2>/dev/null || true
                fi
            fi
        fi

        if [ "$LEGACY_FAILED" -ne 0 ]; then
            echo "PARTIAL_SUCCESS: RouteClue anchor flushed and token released, but legacy token release failed."
            exit 5
        fi

        echo "SUCCESS: RouteClue anchor rules flushed and token released."
        """
    }

    /// Applies the kill switch into the isolated anchor `com.apple/routeclue`.
    /// Сериализовано в едином привилегированном пакете с блокировкой от параллельных вызовов.
    public static func apply(
        _ config: RouteClueConfig,
        stateDir: String = defaultStateDir,
        pfctl: String = defaultPfctlPath
    ) throws -> KillSwitchPlan {
        let plan = try plan(config: config)
        let problems = validate(plan)
        if !problems.isEmpty {
            throw KillSwitchError.validationFailed(problems)
        }

        // Временный защищенный файл правил (mode 0600)
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("rc-pf-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString).conf")
        try plan.rules.write(to: tempFile, atomically: true, encoding: .utf8)
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempFile.path)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        let script = makeApplyScript(rulesFile: tempFile.path, anchor: anchorName, stateDir: stateDir, pfctl: pfctl)
        let result = try Shell.privileged(script)

        if !result.ok {
            if result.combined.contains("FAIL_LOCK") {
                throw KillSwitchError.executionFailed("Параллельная операция управления PF уже выполняется (lock busy).")
            }
            if result.combined.contains("FAIL_REACHABLE") {
                throw KillSwitchError.anchorNotReachable(result.combined)
            }
            if result.combined.contains("FAIL_STALE") {
                throw KillSwitchError.executionFailed("Сохраненный токен ссылается на неактивное состояние PF: \(result.combined)")
            }
            if result.combined.contains("FAIL_TOKEN") {
                throw KillSwitchError.executionFailed("pfctl -E не вернул токен ссылки: \(result.combined)")
            }
            if result.combined.contains("FAIL_SAVE") {
                if result.combined.contains("ROLLBACK_SUCCESS") {
                    throw KillSwitchError.executionFailed("Не удалось сохранить файл токена. Выполнен компенсирующий release токена.")
                } else {
                    throw KillSwitchError.executionFailed("КРИТИЧЕСКАЯ ОШИБКА: Не удалось сохранить токен и не удалось освободить токен. Требуется ручное восстановление: \(result.combined)")
                }
            }
            if result.combined.contains("FAIL_LOAD") {
                if result.combined.contains("ROLLBACK_FAILED") {
                    throw KillSwitchError.executionFailed("Ошибка загрузки правил анкера и сбой отката токена: \(result.combined)")
                } else {
                    throw KillSwitchError.executionFailed("Ошибка загрузки правил анкера: \(result.combined)")
                }
            }
            throw KillSwitchError.executionFailed("Ошибка применения правил PF: \(result.combined)")
        }

        return plan
    }

    /// Disables the kill switch by flushing only the RouteClue anchor rules and releasing owned token.
    public static func disable(
        stateDir: String = defaultStateDir,
        pfctl: String = defaultPfctlPath,
        legacyTokenFile: String? = legacyTokenFileURL.path
    ) throws -> String {
        let script = makeDisableScript(
            anchor: anchorName,
            stateDir: stateDir,
            pfctl: pfctl,
            legacyTokenFile: legacyTokenFile,
            legacyAnchor: legacyAnchorName
        )
        let result = try Shell.privileged(script)

        if result.status == 5 || result.combined.contains("PARTIAL_SUCCESS") {
            return "RouteClue anchor rules flushed and token released, but legacy token release failed: \(result.combined)"
        }

        if !result.ok {
            if result.combined.contains("FAIL_LOCK") {
                throw KillSwitchError.executionFailed("Параллельная операция управления PF уже выполняется (lock busy).")
            }
            if result.combined.contains("FAIL_FLUSH") {
                throw KillSwitchError.executionFailed("Не удалось очистить правила анкера \(anchorName): \(result.combined)")
            }
            if result.combined.contains("FAIL_RELEASE") {
                throw KillSwitchError.executionFailed("Не удалось освободить токен PF: \(result.combined). Файл токена сохранен для повторной попытки.")
            }
            throw KillSwitchError.executionFailed("Ошибка отключения PF: \(result.combined)")
        }

        return "Kill switch disabled, RouteClue anchor rules flushed."
    }

    /// nil means state is unknown (no root privileges to inspect pf or active ruleset unreachable).
    public static func isEnabled(pfctl: String = defaultPfctlPath) -> Bool? {
        // 1. Проверяем правила в нашем анкере
        guard let result = try? Shell.run(pfctl, ["-a", anchorName, "-s", "rules"]), result.ok else {
            return nil
        }
        let rules = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if rules.isEmpty {
            return false
        }

        // 2. PF глобально должен быть включен
        guard let info = try? Shell.run(pfctl, ["-s", "info"]), info.ok else {
            return nil
        }
        if !info.stdout.contains("Status: Enabled") {
            return false
        }

        // 3. Анкер должен быть доказанно достижим из активного ruleset ядра (pfctl -sr)
        guard let activeRules = try? Shell.run(pfctl, ["-sr"]), activeRules.ok else {
            // Если pfctl -sr не удалось выполнить (permission denied или ошибка), статус НЕЛЬЗЯ объявлять true -> возвращаем nil!
            return nil
        }

        let reachability = isAnchorReachable(inRuleset: activeRules.stdout)
        if !reachability.reachable {
            return false
        }

        return true
    }
}
