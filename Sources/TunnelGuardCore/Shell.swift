import Foundation

public struct ShellResult: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
    public var ok: Bool { status == 0 }

    public var combined: String {
        [stdout, stderr].filter { !$0.isEmpty }.joined(separator: "\n")
    }
}

public enum ShellError: Error, CustomStringConvertible {
    case failed(command: String, result: ShellResult)

    public var description: String {
        switch self {
        case let .failed(command, result):
            return "Команда не выполнена: \(command)\n\(result.combined)"
        }
    }
}

/// Тонкая обёртка над Process: без зависимостей и без магии.
public enum Shell {
    @discardableResult
    public static func run(_ executable: String, _ arguments: [String]) throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err

        try process.run()
        // Читаем дочерний вывод до конца, иначе буфер пайпа может заблокировать процесс.
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return ShellResult(
            status: process.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
            stderr: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    @discardableResult
    public static func sh(_ command: String) throws -> ShellResult {
        try run("/bin/sh", ["-c", command])
    }

    /// Проверка прав без запроса пароля.
    public static var isRoot: Bool { geteuid() == 0 }

    /// Выполняет команду от root: сразу, если уже root, иначе через системный диалог авторизации.
    @discardableResult
    public static func privileged(_ command: String) throws -> ShellResult {
        if isRoot { return try sh(command) }

        let escaped = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        let result = try run("/usr/bin/osascript", ["-e", script])
        if !result.ok {
            throw ShellError.failed(command: command, result: result)
        }
        return result
    }
}
