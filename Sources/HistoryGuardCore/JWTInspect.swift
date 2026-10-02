import Foundation

/// Minimal read-only JWT inspection used by scanning: an expired token is low-value, so detection drops it.
public enum JWTInspect {
    /// The `exp` time, if `token` is a JWT whose payload carries a numeric `exp` claim.
    public static func expiry(of token: String) -> Date? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        var b64 = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let exp = (obj["exp"] as? NSNumber)?.doubleValue else { return nil }
        return Date(timeIntervalSince1970: exp)
    }

    /// True only when the token has an `exp` claim in the past. A token without `exp` is never "expired".
    public static func isExpired(_ token: String, now: Date = Date()) -> Bool {
        guard let exp = expiry(of: token) else { return false }
        return exp < now
    }
}
