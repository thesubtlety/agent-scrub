import Foundation
import HistoryGuardCore

/// Decodes a JWT's header and payload (base64url JSON) for read-only inspection, and flags expiry from the
/// `exp` claim. The signature is left alone.
enum JWT {
    static func decode(_ token: String) -> String? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2, let hData = data(parts[0]), let pData = data(parts[1]) else { return nil }
        let header = pretty(hData) ?? String(decoding: hData, as: UTF8.self)
        let payload = pretty(pData) ?? String(decoding: pData, as: UTF8.self)

        var status = ""
        if let obj = try? JSONSerialization.jsonObject(with: pData) as? [String: Any] {
            if let exp = (obj["exp"] as? NSNumber)?.doubleValue {
                let date = Date(timeIntervalSince1970: exp)
                let when = date.formatted(date: .abbreviated, time: .shortened)
                status += date < Date() ? "⚠ EXPIRED — was valid until \(when)\n" : "Valid until \(when)\n"
            }
            if let iat = (obj["iat"] as? NSNumber)?.doubleValue {
                status += "Issued \(Date(timeIntervalSince1970: iat).formatted(date: .abbreviated, time: .shortened))\n"
            }
        }
        return (status.isEmpty ? "" : status + "\n") + "HEADER\n\(header)\n\nPAYLOAD\n\(payload)"
    }

    private static func data(_ s: Substring) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }

    private static func pretty(_ d: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: d),
              let p = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) else { return nil }
        return String(decoding: p, as: UTF8.self)
    }
}

/// Formats a short, masked line of context around an occurrence from bytes the adapter already read. The byte
/// reading lives in the adapter (`currentBytes`) so SQLite cells are handled correctly — reading the database file
/// directly at a cell-relative offset returns schema/page garbage, not the cell's text. The secret is blanked
/// before anything is returned, and nothing is ever stored.
enum Excerpt {
    /// `bytes`/`start` are the adapter's `currentBytes` result: `bytes[0]` sits at offset `start` in the record's
    /// coordinate space, and `recordRange` is the secret's range in that same space.
    static func format(bytes: [UInt8], recordRange: Range<Int>, start: Int, maxLength: Int = 160) -> String? {
        var bytes = bytes
        let lo = recordRange.lowerBound - start
        let hi = min(bytes.count, recordRange.upperBound - start)
        guard lo >= 0, hi >= lo, hi <= bytes.count else { return nil }
        bytes.replaceSubrange(lo..<hi, with: Array("••••".utf8))   // blank the secret before it can be seen

        var text = String(decoding: bytes, as: UTF8.self)
        text = text.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespaces)
        if text.count > maxLength { text = String(text.prefix(maxLength)) + "…" }
        return (start > 0 ? "…" : "") + text
    }
}
