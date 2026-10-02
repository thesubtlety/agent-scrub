import Foundation
import HistoryGuardCore

/// Produces display strings that never contain enough of a secret to reuse it.
public enum Masker {
    static let bullet = "•"

    public static func mask(_ secret: String, kind: SecretKind, spec: MaskSpec) -> String {
        switch kind {
        case .privateKey:
            return "Private key · \(pemType(secret))"
        case .databaseURL:
            return maskURL(secret)
        default:
            break
        }
        let chars = Array(secret)
        // Never reveal more than a third of the value, and never more than prefix+suffix <= 12.
        let budget = min(12, max(0, chars.count / 3))
        var prefix = min(spec.prefix, budget)
        var suffix = min(spec.suffix, max(0, budget - prefix))
        if chars.count < 12 { prefix = 0; suffix = min(2, chars.count / 4) }
        let head = String(chars.prefix(prefix))
        let tail = String(chars.suffix(suffix))
        let hidden = max(4, min(8, chars.count - prefix - suffix))
        return head + String(repeating: bullet, count: hidden) + tail
    }

    static func pemType(_ s: String) -> String {
        if s.contains("BEGIN RSA") { return "RSA" }
        if s.contains("BEGIN EC") { return "EC" }
        if s.contains("BEGIN DSA") { return "DSA" }
        if s.contains("BEGIN OPENSSH") { return "OpenSSH" }
        if s.contains("BEGIN PGP") { return "PGP" }
        if s.contains("BEGIN ENCRYPTED") { return "encrypted PKCS#8" }
        return "PKCS#8"
    }

    static func maskURL(_ s: String) -> String {
        // scheme://user:password@host/... -> scheme://user:••••@host/…
        guard let schemeEnd = s.range(of: "://"),
              let at = s.range(of: "@", range: schemeEnd.upperBound..<s.endIndex) else {
            return String(s.prefix(12)) + "••••"
        }
        let userinfo = s[schemeEnd.upperBound..<at.lowerBound]
        let user = userinfo.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
        var rest = String(s[at.upperBound...])
        if let slash = rest.firstIndex(of: "/") {
            rest = String(rest[..<slash]) + "/…"
        }
        return String(s[..<schemeEnd.upperBound]) + user + ":" + String(repeating: bullet, count: 4) + "@" + rest
    }
}
