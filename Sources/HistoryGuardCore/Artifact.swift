import Foundation

public enum ArtifactKind: String, Codable, Sendable {
    case jsonl
    case json
    case plainText
    case sqlite
    case binary
}

/// One scannable file (or database) inside a store.
public struct Artifact: Hashable, Codable, Sendable {
    public let url: URL
    public let storeID: StoreID
    public let kind: ArtifactKind
    public let identity: FileIdentity
    public let sessionID: String?
    public let projectPath: String?

    public init(url: URL, storeID: StoreID, kind: ArtifactKind, identity: FileIdentity,
                sessionID: String? = nil, projectPath: String? = nil) {
        self.url = url
        self.storeID = storeID
        self.kind = kind
        self.identity = identity
        self.sessionID = sessionID
        self.projectPath = projectPath
    }
}

/// A run of decoded text extracted from an artifact, with enough information to map any range inside it
/// back to the serialized bytes on disk.
public struct ContentRegion: Sendable {
    public let text: String
    public let locator: RecordLocator
    /// Serialized byte offset of `text`'s first byte when `offsetMap` is nil (identity mapping).
    public let baseOffset: Int
    /// For JSON strings: offsetMap[i] is the serialized byte offset of semantic UTF-8 offset i, with one extra
    /// trailing entry for the end. nil means identity (plain text).
    public let offsetMap: [Int]?
    /// True if the serialized form contains escape sequences or non-ASCII bytes within the string body.
    public let hasEscapes: Bool
    /// True when semantic and serialized offsets are known to line up exactly.
    public let offsetsReliable: Bool

    public init(text: String, locator: RecordLocator, baseOffset: Int, offsetMap: [Int]? = nil,
                hasEscapes: Bool = false, offsetsReliable: Bool = true) {
        self.text = text
        self.locator = locator
        self.baseOffset = baseOffset
        self.offsetMap = offsetMap
        self.hasEscapes = hasEscapes
        self.offsetsReliable = offsetsReliable
    }

    /// Map a semantic UTF-8 range (relative to `text`) to a serialized byte range in the artifact.
    public func serializedRange(for semantic: Range<Int>) -> Range<Int> {
        if let map = offsetMap {
            let lo = map[min(semantic.lowerBound, map.count - 1)]
            let hi = map[min(semantic.upperBound, map.count - 1)]
            return lo..<hi
        }
        return (baseOffset + semantic.lowerBound)..<(baseOffset + semantic.upperBound)
    }

    /// Whether the serialized bytes backing `semantic` can be replaced by same-length ASCII without
    /// touching JSON structure.
    public func feasibility(for semantic: Range<Int>) -> RedactionFeasibility {
        guard offsetsReliable else { return .offsetsUnreliable }   // range can't be trusted — never rewrite from it
        guard let map = offsetMap else { return .byteLengthPreserving }
        // Every semantic byte must map to exactly one serialized byte: no escapes inside the match.
        for i in semantic.lowerBound..<semantic.upperBound {
            if map[i + 1] - map[i] != 1 { return .requiresSemanticRewrite }
        }
        return .byteLengthPreserving
    }
}

public enum ArtifactActivity: Hashable, Codable, Sendable {
    case active(reason: String)
    case inactive
    case unknown
}

public struct ScanCursor: Hashable, Codable, Sendable {
    public var fileIdentity: FileIdentity
    public var lastScanOffset: UInt64
    public init(fileIdentity: FileIdentity, lastScanOffset: UInt64) {
        self.fileIdentity = fileIdentity
        self.lastScanOffset = lastScanOffset
    }
}

public struct ArtifactPage: Sendable {
    public let artifacts: [Artifact]
    public let gaps: [CoverageGap]
    public init(artifacts: [Artifact], gaps: [CoverageGap]) {
        self.artifacts = artifacts
        self.gaps = gaps
    }
}

/// Result of extracting text from one artifact.
public struct ExtractedContent: Sendable {
    public let regions: [ContentRegion]
    public let gaps: [CoverageGap]
    public let bytesExamined: UInt64
    public init(regions: [ContentRegion], gaps: [CoverageGap], bytesExamined: UInt64) {
        self.regions = regions
        self.gaps = gaps
        self.bytesExamined = bytesExamined
    }
}

/// Result of a cursor-aware extraction. `scannedFromOffset` is where extraction actually began: 0
/// means a full scan (replace prior occurrences), > 0 means only new bytes were read (append).
public struct DeltaExtraction: Sendable {
    public let content: ExtractedContent
    public let newCursor: ScanCursor
    public let scannedFromOffset: UInt64
    public init(content: ExtractedContent, newCursor: ScanCursor, scannedFromOffset: UInt64) {
        self.content = content
        self.newCursor = newCursor
        self.scannedFromOffset = scannedFromOffset
    }
}
