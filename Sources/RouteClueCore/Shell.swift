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

public enum ShellError: Error, CustomStringConvertible, Sendable {
    case failed(command: String, result: ShellResult)

    public var description: String {
        switch self {
        case let .failed(command, result):
            return "Команда не выполнена: \(command)\n\(result.combined)"
        }
    }
}

/// Безопасная обёртка над Process: без дедлоков буферов, с поддержкой stdin и экранирования.
public enum Shell {
    /// Оборачивает аргумент в одинарные кавычки с безопасным экранированием для POSIX shell.
    public static func quote(_ argument: String) -> String {
        "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private final class BufferBox: @unchecked Sendable {
        var data = Data()
    }

    @discardableResult
    public static func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String]? = nil,
        input: String? = nil
    ) throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let env = environment {
            var fullEnv = ProcessInfo.processInfo.environment
            for (k, v) in env { fullEnv[k] = v }
            process.environment = fullEnv
        }

        let outPipe = Pipe()
        let errPipe = Pipe()
        let inPipe = Pipe()

        process.standardOutput = outPipe
        process.standardError = errPipe
        if input != nil {
            process.standardInput = inPipe
        }

        // Запускаем параллельное чтение stdout и stderr для исключения дедлока при переполнении 64KB буфера pipe.
        let outBox = BufferBox()
        let errBox = BufferBox()
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            outBox.data = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            errBox.data = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        try process.run()

        if let input = input {
            if let data = input.data(using: .utf8) {
                inPipe.fileHandleForWriting.write(data)
            }
            try? inPipe.fileHandleForWriting.close()
        }

        process.waitUntilExit()
        group.wait()

        return ShellResult(
            status: process.terminationStatus,
            stdout: String(decoding: outBox.data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
            stderr: String(decoding: errBox.data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    @discardableResult
    public static func sh(_ command: String, environment: [String: String]? = nil, input: String? = nil) throws -> ShellResult {
        try run("/bin/sh", ["-c", command], environment: environment, input: input)
    }

    /// Проверка прав без запроса пароля.
    public static var isRoot: Bool { geteuid() == 0 }

    /// Выполняет команду от root: сразу, если уже root, иначе через системный диалог авторизации macOS.
    @discardableResult
    public static func privileged(_ command: String) throws -> ShellResult {
        if isRoot { return try sh(command) }

        // Безопасное экранирование для AppleScript строкового литерала
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
