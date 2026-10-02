import Foundation

/// One byte range to overwrite in place. Built from a fresh scan; applied only if the artifact still holds the
/// same bytes (checked by HMAC of the preimage, so the plan itself never stores plaintext).
public struct RedactionTarget: Identifiable, Sendable, Codable, Hashable {
    public let id: UUID
    public let occurrenceID: UUID
    public let secretID: UUID
    public let fingerprint: SecretFingerprint
    public let adapterID: AdapterID
    public let storeID: StoreID
    public let artifactURL: URL
    /// Inode identity at planning time. Size may grow (append-only stores) but the inode must not change.
    public let expectedIdentity: FileIdentity
    public let range: Range<Int>
    /// HMAC over the exact serialized bytes currently at `range`.
    public let preimage: SecretFingerprint
    /// Printable ASCII, never `"` or `\`. Same byte count as `range` for an in-place overwrite; a different
    /// length marks a semantic rewrite (the record's line is resized and rewritten).
    public let replacement: [UInt8]
    public let locator: RecordLocator

    /// True for the fast same-length overwrite; false when the record must be resized (semantic rewrite).
    public var preservesLength: Bool { replacement.count == range.count }

    public init(id: UUID = UUID(), occurrenceID: UUID, secretID: UUID, fingerprint: SecretFingerprint, adapterID: AdapterID,
                storeID: StoreID, artifactURL: URL, expectedIdentity: FileIdentity, range: Range<Int>,
                preimage: SecretFingerprint, replacement: [UInt8], locator: RecordLocator) {
        self.id = id
        self.occurrenceID = occurrenceID
        self.secretID = secretID
        self.fingerprint = fingerprint
        self.adapterID = adapterID
        self.storeID = storeID
        self.artifactURL = artifactURL
        self.expectedIdentity = expectedIdentity
        self.range = range
        self.preimage = preimage
        self.replacement = replacement
        self.locator = locator
    }
}

/// Why an occurrence was not put into a plan. Every one of these is shown to the user; none is silent.
public enum RedactionDeferral: Sendable, Codable, Hashable, CustomStringConvertible {
    case storeReadOnly
    case requiresSemanticRewrite
    /// Inside a binary record we can't fully parse (e.g. a msgpack cell). Not auto-redacted, but removable by the
    /// opt-in raw-byte rewrite — the UI offers that as a per-item choice.
    case binaryRecordNeedsForce
    /// The raw-byte rewrite was requested but the secret's exact bytes weren't found exactly once in the record.
    case binaryRecordUnredactable
    case artifactActive(reason: String)
    case artifactChanged(detail: String = "")
    case unreadable(String)

    public var description: String {
        switch self {
        case .storeReadOnly: "store is read-only for this adapter version"
        case .requiresSemanticRewrite: "record not cleanly decodable (non-UTF-8); left as-is"
        case .binaryRecordNeedsForce: "inside a binary record we can't fully parse; use force-redact to remove it"
        case .binaryRecordUnredactable: "couldn't locate the secret's exact bytes uniquely in the binary record"
        case let .artifactActive(r): "artifact is in use: \(r)"
        case let .artifactChanged(d): d.isEmpty ? "artifact changed since it was scanned; rescan needed" : "artifact changed: \(d)"
        case let .unreadable(e): "unreadable: \(e)"
        }
    }
}

public struct RedactionPlan: Sendable, Codable {
    public var targets: [RedactionTarget]
    public var deferred: [UUID: RedactionDeferral]
    public init(targets: [RedactionTarget], deferred: [UUID: RedactionDeferral]) {
        self.targets = targets
        self.deferred = deferred
    }
}

public enum RedactionOutcome: Sendable, Codable, Hashable, CustomStringConvertible {
    case applied
    /// Bytes at the range already equal the replacement (plan re-applied after a crash).
    case alreadyApplied
    case preimageMismatch
    case identityMismatch
    case postCheckFailedAndRolledBack(String)
    case ioError(String)

    public var description: String {
        switch self {
        case .applied: "applied"
        case .alreadyApplied: "already applied"
        case .preimageMismatch: "bytes changed since planning; not written"
        case .identityMismatch: "file replaced since planning; not written"
        case let .postCheckFailedAndRolledBack(e): "record invalid after write, restored original: \(e)"
        case let .ioError(e): "I/O error: \(e)"
        }
    }

    public var succeeded: Bool { self == .applied || self == .alreadyApplied }
}

public struct RedactionResult: Sendable, Codable {
    public var outcomes: [UUID: RedactionOutcome]   // keyed by target id
    public init(outcomes: [UUID: RedactionOutcome]) { self.outcomes = outcomes }
    public var appliedCount: Int { outcomes.values.filter(\.succeeded).count }
    public var failed: [UUID: RedactionOutcome] { outcomes.filter { !$0.value.succeeded } }
}

/// Builds same-length replacement bytes. Descriptive when there is room, otherwise asterisks.
public enum Replacement {
    static let safe: Set<UInt8> = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:[]*_-".utf8)

    /// The human-readable marker a redaction writes in place of the secret (before any `*` padding).
    public static func marker(kind: SecretKind, fingerprint: SecretFingerprint) -> String {
        "[REDACTED:\(shortLabel(kind)):\(fingerprint.shortHex.suffix(4).uppercased())]"
    }

    public static func bytes(length: Int, kind: SecretKind, fingerprint: SecretFingerprint) -> [UInt8] {
        let tag = marker(kind: kind, fingerprint: fingerprint)
        var out: [UInt8]
        if tag.utf8.count <= length {
            out = Array(tag.utf8) + Array(repeating: UInt8(ascii: "*"), count: length - tag.utf8.count)
        } else {
            out = Array(repeating: UInt8(ascii: "*"), count: length)
        }
        precondition(out.allSatisfy { safe.contains($0) })
        return out
    }

    static func shortLabel(_ kind: SecretKind) -> String {
        switch kind {
        case .githubToken: "GITHUB"
        case .awsAccessKeyID, .awsSecretAccessKey: "AWS"
        case .stripeKey: "STRIPE"
        case .slackToken: "SLACK"
        case .openAIKey: "OPENAI"
        case .anthropicKey: "ANTHROPIC"
        case .googleAPIKey: "GOOGLE"
        case .vendorAPIKey: "APIKEY"
        case .privateKey: "PRIVATEKEY"
        case .bearerToken: "BEARER"
        case .jwt: "JWT"
        case .databaseURL: "DBURL"
        case .genericPassword: "PASSWORD"
        case .genericAPIKey: "APIKEY"
        case .genericSecret: "SECRET"
        }
    }
}
