import Foundation

public enum TargetInputError: Error, LocalizedError, Sendable, Equatable {
    case emptyInput
    case invalidHost(String)
    case invalidURL

    public var errorDescription: String? {
        switch self {
        case .emptyInput:
            return "Введена пустая строка или пробелы."
        case let .invalidHost(host):
            return "Некорректный адрес или имя хоста: '\(host)'."
        case .invalidURL:
            return "Не удалось разобрать URL: некорректный формат адреса."
        }
    }
}

public enum TargetInputNormalizer {
    /// Чистая нормализация введенного пользователем хоста или URL.
    /// Безопасно удаляет credentials/userinfo, нормализует схемы, порты, IPv6 и валидирует синтаксис БЕЗ отправки сетевых/DNS-запросов.
    public static func normalize(_ rawInput: String) -> Result<String, TargetInputError> {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .failure(.emptyInput)
        }

        var candidate = trimmed

        // 1. Предварительно отсекаем userinfo (user:password@) до парсинга URL,
        // чтобы учетные данные/токены гарантированно не попали в URL парсер или сообщения об ошибках
        if let schemeRange = candidate.range(of: "://") {
            let afterScheme = String(candidate[schemeRange.upperBound...])
            if let atIndex = afterScheme.firstIndex(of: "@") {
                let hostAndRest = String(afterScheme[afterScheme.index(after: atIndex)...])
                candidate = String(candidate[..<schemeRange.upperBound]) + hostAndRest
            }
        } else if let atIndex = candidate.firstIndex(of: "@") {
            candidate = String(candidate[candidate.index(after: atIndex)...])
        }

        // 2. Проверяем наличие URL схемы (http://, https://, etc.)
        if candidate.contains("://") {
            guard let url = URL(string: candidate) else {
                return .failure(.invalidURL)
            }
            guard let host = url.host, !host.isEmpty else {
                return .failure(.invalidURL)
            }
            candidate = host
        } else if candidate.contains("/") {
            // Строка вида "example.com/path" или "192.168.1.1/path"
            if let firstSlash = candidate.firstIndex(of: "/") {
                candidate = String(candidate[..<firstSlash])
            }
        }

        // 3. Обработка портов и скобок IPv6
        if candidate.hasPrefix("[") {
            // Скобочный IPv6 вида [2001:db8::1] или [2001:db8::1]:8080
            guard let closeBracket = candidate.firstIndex(of: "]") else {
                return .failure(.invalidHost(candidate))
            }
            let ipv6Body = String(candidate[candidate.index(after: candidate.startIndex)..<closeBracket])
            candidate = ipv6Body
        } else if candidate.contains(":") {
            // Проверяем: это IPv6 (содержит >1 двоеточия) или host:port (ровно 1 двоеточие)
            let colonCount = candidate.filter { $0 == ":" }.count
            if colonCount == 1 {
                // host:port или ipv4:port
                let parts = candidate.split(separator: ":", omittingEmptySubsequences: false)
                if parts.count == 2 && !parts[0].isEmpty {
                    candidate = String(parts[0])
                }
            }
            // Если colonCount > 1, это сырой unbracketed IPv6 (например, 2001:db8::1) — НЕ разбиваем по двоеточию!
        }

        // 4. Очистка завершающих точек в FQDN (например, "example.com.")
        while candidate.hasSuffix(".") && candidate.count > 1 {
            candidate.removeLast()
        }

        // 5. Регистронезависимая нормализация: приведение имени хоста к нижнему регистру
        candidate = candidate.lowercased()

        // 6. Строгая синтаксическая валидация
        if isValidIPv4(candidate) {
            return .success(candidate)
        }

        if isValidIPv6(candidate) {
            return .success(candidate)
        }

        if isValidHostname(candidate) {
            return .success(candidate)
        }

        return .failure(.invalidHost(candidate))
    }

    public static func isValidIPv4(_ address: String) -> Bool {
        RouteManager.parseIPv4(address) != nil
    }

    public static func isValidIPv6(_ address: String) -> Bool {
        var sin6 = sockaddr_in6()
        return inet_pton(AF_INET6, address, &sin6.sin6_addr) == 1
    }

    public static func isValidHostname(_ host: String) -> Bool {
        guard !host.isEmpty && host.count <= 253 else { return false }
        if host.contains(" ") || host.contains("/") || host.contains(":") || host.contains("@") {
            return false
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        for label in labels {
            guard !label.isEmpty && label.count <= 63 else { return false }
            // RFC 1123 label: [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?
            guard let first = label.first, first.isLetter || first.isNumber else { return false }
            guard let last = label.last, last.isLetter || last.isNumber else { return false }
            for char in label {
                guard char.isLetter || char.isNumber || char == "-" else { return false }
            }
        }
        return true
    }
}
