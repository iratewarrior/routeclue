import Foundation

/// Минимальный DNS-клиент: один A-запрос по UDP, без зависимостей.
/// Нужен для диагностики — проверить, отвечает ли конкретный сервер вообще,
/// а не «открыт ли порт» (открытый порт при перехвате DNS ничего не значит).
public enum DNSQuery {
    public struct Answer: Sendable {
        public let rcode: Int
        public let addresses: [String]
        public let elapsed: TimeInterval
        public var ok: Bool { rcode == 0 }
    }

    public static func a(_ name: String, server: String, timeout: TimeInterval = 2) -> Answer? {
        guard let serverBytes = ipv4Bytes(server) else { return nil }
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let packet = buildQuery(name: name, id: 0x7A21)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(53).bigEndian
        withUnsafeMutableBytes(of: &addr.sin_addr) { raw in
            raw.copyBytes(from: serverBytes)
        }

        let started = Date()
        let sent = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                sendto(fd, packet, packet.count, 0, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard sent == packet.count else { return nil }

        var buffer = [UInt8](repeating: 0, count: 2048)
        let received = recv(fd, &buffer, buffer.count, 0)
        guard received > 0 else { return nil }

        let elapsed = Date().timeIntervalSince(started)
        let response = Array(buffer.prefix(received))
        let rcode = Int(response.count > 3 ? response[3] & 0x0F : 15)
        return Answer(rcode: rcode, addresses: parseAddresses(response), elapsed: elapsed)
    }

    // MARK: - Пакеты

    public static func buildQuery(name: String, id: UInt16) -> [UInt8] {
        var bytes: [UInt8] = [
            UInt8(id >> 8), UInt8(id & 0xFF),
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]
        for label in name.split(separator: ".") {
            let utf8 = Array(label.utf8)
            bytes.append(UInt8(utf8.count))
            bytes.append(contentsOf: utf8)
        }
        bytes.append(0)
        bytes.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A, IN
        return bytes
    }

    public static func parseAddresses(_ data: [UInt8]) -> [String] {
        guard data.count > 12 else { return [] }
        let qd = Int(data[4]) << 8 | Int(data[5])
        let an = Int(data[6]) << 8 | Int(data[7])
        guard an > 0 else { return [] }

        var offset = 12
        for _ in 0..<qd {
            guard let next = skipName(data, offset) else { return [] }
            offset = next + 4
        }

        var addresses: [String] = []
        for _ in 0..<an {
            guard let next = skipName(data, offset) else { break }
            offset = next
            guard offset + 10 <= data.count else { break }
            let type = Int(data[offset]) << 8 | Int(data[offset + 1])
            let klass = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
            let length = Int(data[offset + 8]) << 8 | Int(data[offset + 9])
            offset += 10
            guard offset + length <= data.count else { break }
            if type == 1, klass == 1, length == 4 {
                addresses.append("\(data[offset]).\(data[offset + 1]).\(data[offset + 2]).\(data[offset + 3])")
            }
            offset += length
        }
        return addresses
    }

    private static func skipName(_ data: [UInt8], _ start: Int) -> Int? {
        var index = start
        while index < data.count {
            let length = Int(data[index])
            if length == 0 { return index + 1 }
            if length & 0xC0 == 0xC0 { return index + 2 } // указатель на сжатие
            index += length + 1
        }
        return nil
    }

    private static func ipv4Bytes(_ string: String) -> [UInt8]? {
        let parts = string.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : nil
    }
}
