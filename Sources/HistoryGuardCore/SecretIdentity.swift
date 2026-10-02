import Foundation

/// HMAC-SHA256 output identifying a secret without storing it. Never derived from plaintext without the installation key.
public struct SecretFingerprint: Hashable, Codable, Sendable, CustomStringConvertible {
    public let bytes: Data

    public init(bytes: Data) {
        precondition(bytes.count == 32, "fingerprint must be 32 bytes")
        self.bytes = bytes
    }

    /// Short, log-safe prefix. Not sufficient to identify the secret outside this installation.
    public var shortHex: String {
        bytes.prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    /// Full 64-char hex; used as the key for retention policies.
    public var hex: String { bytes.map { String(format: "%02x", $0) }.joined() }

    /// A UUID derived deterministically from the fingerprint, so a secret keeps the SAME identity across rescans
    /// (used as `SecretIdentity.id`). The same fingerprint always yields the same UUID; different fingerprints
    /// effectively never collide (these bytes are an HMAC).
    public var stableID: UUID {
        var b = Array(bytes.prefix(16))
        while b.count < 16 { b.append(0) }
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    public var description: String { "fp:\(shortHex)" }
}

public struct SecretIdentity: Identifiable, Hashable, Codable, Sendable {
    /// Derived from the fingerprint so it is stable across rescans (a fresh per-scan UUID made the detail view
    /// lose its selection when the index pruned and re-added a fingerprint).
    public var id: UUID { fingerprint.stableID }
    public let fingerprint: SecretFingerprint
    public let kind: SecretKind
    /// Short human label from the detecting rule, e.g. "GitHub PAT" or "Cloudflare API Key".
    public let label: String
    /// Display string that reveals at most a recognizable prefix and the last few characters.
    public let maskedDisplay: String
    public var confidence: Confidence
    public var firstSeen: Date
    public var lastSeen: Date

    public init(fingerprint: SecretFingerprint, kind: SecretKind, label: String,
                maskedDisplay: String, confidence: Confidence, firstSeen: Date, lastSeen: Date) {
        self.fingerprint = fingerprint
        self.kind = kind
        self.label = label
        self.maskedDisplay = maskedDisplay
        self.confidence = confidence
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    /// Stable UI alias such as "GitHub PAT · 91D4". Uses the fingerprint, not the plaintext.
    public var alias: String {
        "\(label) · \(fingerprint.shortHex.suffix(4).uppercased())"
    }
}
