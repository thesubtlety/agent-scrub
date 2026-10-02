import Foundation
import HistoryGuardCore

/// A single detection from one artifact, before it is merged into a cross-artifact identity index.
/// Carries no secret plaintext.
public struct RawFinding: Sendable {
    public let fingerprint: SecretFingerprint
    public let kind: SecretKind
    public let label: String
    public let maskedDisplay: String
    public let confidence: Confidence
    public let adapterID: AdapterID
    public let storeID: StoreID
    public let artifactURL: URL
    public let fileIdentity: FileIdentity
    public let sessionID: String?
    public let projectPath: String?
    public let recordLocator: RecordLocator
    public let serializedByteRange: Range<Int>
    public let feasibility: RedactionFeasibility

    public init(fingerprint: SecretFingerprint, kind: SecretKind, label: String, maskedDisplay: String,
                confidence: Confidence, adapterID: AdapterID, storeID: StoreID, artifactURL: URL,
                fileIdentity: FileIdentity, sessionID: String?, projectPath: String?,
                recordLocator: RecordLocator, serializedByteRange: Range<Int>, feasibility: RedactionFeasibility) {
        self.fingerprint = fingerprint
        self.kind = kind
        self.label = label
        self.maskedDisplay = maskedDisplay
        self.confidence = confidence
        self.adapterID = adapterID
        self.storeID = storeID
        self.artifactURL = artifactURL
        self.fileIdentity = fileIdentity
        self.sessionID = sessionID
        self.projectPath = projectPath
        self.recordLocator = recordLocator
        self.serializedByteRange = serializedByteRange
        self.feasibility = feasibility
    }
}

/// Result of a delta (or full) rescan of one artifact. `scannedFromOffset == 0` means a full scan
/// (replace); > 0 means an append. The explicit init defaults it to 0 so test fixtures stay terse.
public struct ArtifactDelta: Sendable {
    public let findings: [RawFinding]
    public let gaps: [CoverageGap]
    public let bytesExamined: UInt64
    public let newCursor: ScanCursor
    public let scannedFromOffset: UInt64
    public init(findings: [RawFinding], gaps: [CoverageGap], bytesExamined: UInt64,
                newCursor: ScanCursor, scannedFromOffset: UInt64 = 0) {
        self.findings = findings
        self.gaps = gaps
        self.bytesExamined = bytesExamined
        self.newCursor = newCursor
        self.scannedFromOffset = scannedFromOffset
    }
}
