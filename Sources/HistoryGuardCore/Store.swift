import Foundation

/// Why a store is (or is not) scanned. Drives the Coverage UI.
public enum StoreTier: String, Codable, Sendable {
    /// Conversation history: prompts, transcripts, tool output. Scanned by default.
    case conversation
    /// Persistent AI memory. Scanned by default.
    case memory
    /// Residue: caches, debug output, file snapshots. Scanned when extended scanning is on.
    case extended
    /// Configuration, credentials, plugins. Enumerated for coverage but never scanned or mutated.
    case excluded
}

public struct StoreCapabilities: OptionSet, Codable, Sendable, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    public static let detect = StoreCapabilities(rawValue: 1 << 0)
    public static let redactWhileActive = StoreCapabilities(rawValue: 1 << 1)
    public static let redactWhenInactive = StoreCapabilities(rawValue: 1 << 2)
    public static let verify = StoreCapabilities(rawValue: 1 << 3)

    public static let readOnly: StoreCapabilities = [.detect, .verify]
}

public enum SchemaStatus: Hashable, Codable, Sendable {
    case known(version: String)
    case unknown(detail: String)
    case notApplicable
}

public struct StoreDescriptor: Identifiable, Hashable, Codable, Sendable {
    public var id: StoreID
    public let adapterID: AdapterID
    public let displayName: String
    /// Paths (files or directories) that make up this store. Missing paths are fine: the store is then "present: false".
    public let locations: [URL]
    public let tier: StoreTier
    public let capabilities: StoreCapabilities
    public let schema: SchemaStatus
    public let present: Bool
    /// Human-readable reason when tier == .excluded.
    public let exclusionReason: String?

    public init(id: StoreID, adapterID: AdapterID, displayName: String, locations: [URL], tier: StoreTier,
                capabilities: StoreCapabilities, schema: SchemaStatus = .notApplicable, present: Bool,
                exclusionReason: String? = nil) {
        self.id = id
        self.adapterID = adapterID
        self.displayName = displayName
        self.locations = locations
        self.tier = tier
        self.capabilities = capabilities
        self.schema = schema
        self.present = present
        self.exclusionReason = exclusionReason
    }
}

/// Anything that prevents a store, artifact or record from being fully covered. Every gap must be shown
/// to the user before a "clean" state is displayed.
public struct CoverageGap: Hashable, Codable, Sendable, CustomStringConvertible {
    public enum Reason: Hashable, Codable, Sendable {
        /// A directory or file at the adapter root that this adapter version does not recognise.
        case unknownStore
        case unsupportedSchema(detail: String)
        case unreadable(error: String)
        case oversizeArtifact(bytes: UInt64, limit: UInt64)
        case oversizeRecord(line: Int, offset: Int, limit: Int)
        case corruptRecord(line: Int, detail: String)
        case truncatedTail(line: Int)
        case excludedByPolicy(reason: String)
        case skippedSymlink(target: String)
        case binaryArtifact
        case offsetsUnreliable(detail: String)
    }

    public let adapterID: AdapterID
    public let storeID: StoreID?
    public let path: String
    public let reason: Reason

    public init(adapterID: AdapterID, storeID: StoreID?, path: String, reason: Reason) {
        self.adapterID = adapterID
        self.storeID = storeID
        self.path = path
        self.reason = reason
    }

    public var description: String { "\(storeID?.rawValue ?? "-") \(path): \(reason)" }

    /// Gaps that block a "verified clean" claim. Policy exclusions are shown but do not block.
    public var blocksCleanClaim: Bool {
        switch reason {
        case .excludedByPolicy, .binaryArtifact: false
        default: true
        }
    }
}
