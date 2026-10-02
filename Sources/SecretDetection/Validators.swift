import Foundation

/// Offline format validators. A validator returning false means the value cannot be a real credential of
/// that format, so the finding is dropped (mirrors gitleaks/geiger prefix checksum handling).
public enum Validators {
    public static func validate(_ id: String, secret: String) -> Bool {
        switch id {
        case "github-crc32": return githubChecksumValid(secret)
        default: return true
        }
    }

    /// Classic GitHub tokens: 4-char prefix, 30-char body, 6-char base62 CRC32 of the body (alphabet 0-9A-Za-z).
    /// Other lengths (fine-grained PATs, long refresh tokens) are not checksum-validated here.
    public static func githubChecksumValid(_ token: String) -> Bool {
        guard token.count == 40, token.hasPrefix("gh"), token.dropFirst(3).first == "_" else { return true }
        let body = String(token.dropFirst(4).prefix(30))
        let check = String(token.suffix(6))
        return base62(crc32(Array(body.utf8))) == check
    }

    static let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    static func base62(_ value: UInt32) -> String {
        var n = value
        var out: [Character] = []
        while n > 0 {
            out.insert(alphabet[Int(n % 62)], at: 0)
            n /= 62
        }
        while out.count < 6 { out.insert("0", at: 0) }
        return String(out)
    }

    static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        for b in bytes { c = crcTable[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFF_FFFF
    }
}
