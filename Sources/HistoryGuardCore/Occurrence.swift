import Foundation

/// Where inside an artifact a secret was found. Enough to re-locate it for verification and redaction.
public enum RecordLocator: Hashable, Codable, Sendable, CustomStringConvertible {
    /// A JSONL record: 0-based line index, byte offset of the line start, and a JSON pointer to the string value.
    case jsonlRecord(line: Int, lineOffset: Int, pointer: String)
    /// A whole-file JSON document with a JSON pointer.
    case jsonDocument(pointer: String)
    /// A plain-text (or otherwise opaque) file.
    case plainFile
    /// A SQLite cell.
    case sqliteCell(table: String, rowid: Int64, column: String)

    public var description: String {
        switch self {
        case let .jsonlRecord(line, _, pointer): "line \(line) \(pointer)"
        case let .jsonDocument(pointer): pointer
        case .plainFile: "file"
        case let .sqliteCell(table, rowid, column): "\(table)[\(rowid)].\(column)"
        }
    }
}

public enum OccurrenceState: String, Codable, Sendable {
    case detected
    case pendingRedaction
    case redacted
    case verifiedClean
    case keptTemporarily
    case allowedPermanently
    case unsupportedStore
    case failedToRedact
}

/// How the bytes could be rewritten in place. Decided at detection time so the UI can show
/// "Redaction requires inactive rewrite" instead of promising an immediate patch.
public enum RedactionFeasibility: String, Codable, Sendable {
    /// The serialized bytes are plain ASCII with no escapes; a same-length ASCII replacement is valid.
    case byteLengthPreserving
    /// Serialized form contains escapes or multi-byte sequences; needs a semantic rewrite of the record.
    case requiresSemanticRewrite
    /// The decoded text didn't round-trip to the raw bytes (invalid UTF-8), so the byte range can't be trusted —
    /// never rewrite from it.
    case offsetsUnreliable
    /// Store is read-only for this adapter version.
    case unsupported

    /// How a redactor should edit the bytes for this feasibility. The decision lives here as one exhaustive
    /// switch, rather than scattered `==` checks, so changing or adding a feasibility forces every decision site
    /// (replacement kind, active-session safety, store constraints) to be reconsidered by the compiler.
    public enum EditKind: Sendable, Equatable {
        /// Overwrite the serialized range in place with an equal-length ASCII marker.
        case sameLengthInPlace
        /// Rewrite the record at a possibly different length (resize).
        case resizeRecord
        /// Offsets can't be trusted, so locate the secret's exact bytes and overwrite them equal-length
        /// (binary-safe). The engine only attempts this when the caller opts in; otherwise it defers.
        case rawByteSameLength
        /// Not redactable by this adapter version.
        case notRedactable
    }

    public var editKind: EditKind {
        switch self {
        case .byteLengthPreserving: .sameLengthInPlace
        case .requiresSemanticRewrite: .resizeRecord
        case .offsetsUnreliable: .rawByteSameLength
        case .unsupported: .notRedactable
        }
    }
}

public struct SecretOccurrence: Identifiable, Hashable, Codable, Sendable {
    public let id: UUID
    public let secretID: UUID
    public let fingerprint: SecretFingerprint

    public let adapterID: AdapterID
    public let storeID: StoreID

    public let artifactURL: URL
    public let fileIdentity: FileIdentity
    public let sessionID: String?
    public let projectPath: String?

    public let recordLocator: RecordLocator
    /// Byte range of the *serialized* match inside the artifact (what a redactor would overwrite).
    public let serializedByteRange: Range<Int>
    public let feasibility: RedactionFeasibility

    public let discoveredAt: Date
    public var state: OccurrenceState

    public init(id: UUID = UUID(), secretID: UUID, fingerprint: SecretFingerprint,
                adapterID: AdapterID, storeID: StoreID, artifactURL: URL, fileIdentity: FileIdentity,
                sessionID: String?, projectPath: String?, recordLocator: RecordLocator,
                serializedByteRange: Range<Int>, feasibility: RedactionFeasibility,
                discoveredAt: Date, state: OccurrenceState = .detected) {
        self.id = id
        self.secretID = secretID
        self.fingerprint = fingerprint
        self.adapterID = adapterID
        self.storeID = storeID
        self.artifactURL = artifactURL
        self.fileIdentity = fileIdentity
        self.sessionID = sessionID
        self.projectPath = projectPath
        self.recordLocator = recordLocator
        self.serializedByteRange = serializedByteRange
        self.feasibility = feasibility
        self.discoveredAt = discoveredAt
        self.state = state
    }
}

public enum RetentionPolicy: Hashable, Codable, Sendable {
    case redactNow
    case redactWhenSessionEnds
    case keepUntil(Date)
    case alwaysRedact
    case alwaysKeep
    case falsePositive
}
