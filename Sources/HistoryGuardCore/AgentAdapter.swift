import Foundation

public struct AgentInstallation: Hashable, Codable, Sendable {
    public let adapterID: AdapterID
    public let rootURL: URL
    /// Best-effort agent version string, if the adapter could determine one.
    public let version: String?
    public init(adapterID: AdapterID, rootURL: URL, version: String?) {
        self.adapterID = adapterID
        self.rootURL = rootURL
        self.version = version
    }
}

public enum AdapterError: Error, Sendable, CustomStringConvertible {
    case notSupported(String)
    case artifactChanged(URL)
    case unreadable(URL, String)

    public var description: String {
        switch self {
        case let .notSupported(s): "not supported: \(s)"
        case let .artifactChanged(u): "artifact changed: \(u.path)"
        case let .unreadable(u, e): "unreadable \(u.path): \(e)"
        }
    }
}

public struct VerificationResult: Sendable {
    public let fingerprint: SecretFingerprint
    public let scannedStores: Set<StoreID>
    public let skippedStores: [CoverageGap]
    public let occurrencesRemaining: [SecretOccurrence]
    public let completedAt: Date

    public init(fingerprint: SecretFingerprint, scannedStores: Set<StoreID>, skippedStores: [CoverageGap],
                occurrencesRemaining: [SecretOccurrence], completedAt: Date) {
        self.fingerprint = fingerprint
        self.scannedStores = scannedStores
        self.skippedStores = skippedStores
        self.occurrencesRemaining = occurrencesRemaining
        self.completedAt = completedAt
    }

    /// The only condition under which the UI may say "0 copies remain".
    public var isVerifiedClean: Bool {
        occurrencesRemaining.isEmpty && !skippedStores.contains(where: \.blocksCleanClaim)
    }
}

public protocol AgentAdapter: Sendable {
    var id: AdapterID { get }
    var displayName: String { get }

    func discoverInstallations() async -> [AgentInstallation]
    func enumerateStores(installation: AgentInstallation) async throws -> (stores: [StoreDescriptor], gaps: [CoverageGap])
    func enumerateArtifacts(store: StoreDescriptor, cursor: ScanCursor?) async throws -> ArtifactPage
    func extractScannableContent(artifact: Artifact) async throws -> ExtractedContent
    func activeState(artifact: Artifact) async -> ArtifactActivity

    /// Scans only what is new since `cursor`. The default rescans the whole artifact (scannedFromOffset 0);
    /// adapters override it for append-only formats (see ClaudeCodeAdapter for JSONL).
    func extractDelta(artifact: Artifact, from cursor: ScanCursor?) async throws -> DeltaExtraction

    /// Current serialized bytes around an occurrence, for re-verification before planning. Returns the bytes and
    /// the absolute offset of `bytes[0]` in the record's coordinate space. The default reads the artifact file;
    /// database-backed adapters read the cell instead.
    func currentBytes(for occurrence: SecretOccurrence, before: Int, after: Int) throws -> (bytes: [UInt8], start: Int)?

    /// The full raw bytes of the record that holds this occurrence — the whole SQLite cell value, or the whole
    /// file for a file-backed record. Used only by the opt-in raw-byte redaction, which can't trust the decoded
    /// offsets and instead searches the raw bytes for the secret. The default reads the whole file; database-backed
    /// adapters override to read the cell.
    func rawContainerBytes(for occurrence: SecretOccurrence) throws -> [UInt8]?

    /// Adapter-specific veto before an occurrence is planned (read-only store, schema not understood, …).
    /// Activity and feasibility are checked by the redaction engine; this is for store-level constraints.
    func redactionConstraint(for occurrence: SecretOccurrence, in store: StoreDescriptor) -> RedactionDeferral?

    /// Overwrites the planned byte ranges in place after re-verifying identity and preimage, validates the
    /// affected records, and rolls back any write whose record no longer parses. `verifyPreimage` is supplied
    /// by the redaction engine, which holds the installation key; adapters never see it.
    func apply(plan: RedactionPlan, verifyPreimage: @Sendable @escaping ([UInt8], RedactionTarget) -> Bool) async throws -> RedactionResult
}

public extension AgentAdapter {
    func extractDelta(artifact: Artifact, from cursor: ScanCursor?) async throws -> DeltaExtraction {
        let content = try await extractScannableContent(artifact: artifact)
        let identity = try FileIdentity.read(at: artifact.url)
        return DeltaExtraction(content: content,
                               newCursor: ScanCursor(fileIdentity: identity, lastScanOffset: identity.size),
                               scannedFromOffset: 0)
    }

    func currentBytes(for occurrence: SecretOccurrence, before: Int, after: Int) throws -> (bytes: [UInt8], start: Int)? {
        let range = occurrence.serializedByteRange
        let fh = try FileHandle(forReadingFrom: occurrence.artifactURL)
        defer { try? fh.close() }
        let start = max(0, range.lowerBound - before)
        try fh.seek(toOffset: UInt64(start))
        guard let data = try fh.read(upToCount: (range.upperBound + after) - start), data.count >= range.upperBound - start else { return nil }
        return (Array(data), start)
    }

    func rawContainerBytes(for occurrence: SecretOccurrence) throws -> [UInt8]? {
        Array(try Data(contentsOf: occurrence.artifactURL))
    }
}
