import Foundation
import HistoryGuardCore

public struct ScanOptions: Sendable {
    /// Which store tiers to scan. `.excluded` is never scanned regardless of this set.
    public var tiers: Set<StoreTier>
    public init(includeExtended: Bool = false) {
        tiers = includeExtended ? [.conversation, .memory, .extended] : [.conversation, .memory]
    }
}

/// Read-only result of one full pass over one installation. Contains no secret plaintext.
public struct ScanReport: Codable, Sendable {
    public let installation: AgentInstallation
    public let stores: [StoreDescriptor]
    public var gaps: [CoverageGap]
    public var secrets: [SecretIdentity]
    public var occurrences: [SecretOccurrence]
    /// Artifacts containing findings that looked active at scan time.
    public var activeArtifacts: [URL: String]
    public var artifactsScanned: Int
    public var bytesExamined: UInt64
    public let startedAt: Date
    public var finishedAt: Date

    public init(installation: AgentInstallation, stores: [StoreDescriptor], gaps: [CoverageGap],
                secrets: [SecretIdentity], occurrences: [SecretOccurrence], activeArtifacts: [URL: String],
                artifactsScanned: Int, bytesExamined: UInt64, startedAt: Date, finishedAt: Date) {
        self.installation = installation
        self.stores = stores
        self.gaps = gaps
        self.secrets = secrets
        self.occurrences = occurrences
        self.activeArtifacts = activeArtifacts
        self.artifactsScanned = artifactsScanned
        self.bytesExamined = bytesExamined
        self.startedAt = startedAt
        self.finishedAt = finishedAt
    }

    public var scannedStoreIDs: Set<StoreID> {
        Set(stores.filter { $0.present && $0.tier != .excluded }.map(\.id))
    }

    /// True only when nothing was found *and* nothing blocked coverage. This is the only "clean" the UI may show.
    public var isVerifiedClean: Bool {
        occurrences.isEmpty && !gaps.contains(where: \.blocksCleanClaim)
    }

    public func occurrences(of secret: SecretIdentity) -> [SecretOccurrence] {
        occurrences.filter { $0.secretID == secret.id }
    }
}

public struct ScanEngine: Sendable {
    public let adapter: any AgentAdapter
    public let scanner: SecretScanner
    public let fingerprinter: Fingerprinter
    public let walker = JSONStringWalker()

    public init(adapter: any AgentAdapter, scanner: SecretScanner, fingerprinter: Fingerprinter) {
        self.adapter = adapter
        self.scanner = scanner
        self.fingerprinter = fingerprinter
    }

    /// Detection drops expired JWTs (same intent as not flagging a bare AWS key ID): low value, just noise.
    static func isExpiredJWT(_ match: SecretMatch) -> Bool {
        match.kind == .jwt && JWTInspect.isExpired(match.plaintext)
    }

    /// In a region whose bytes don't round-trip (binary / lossy-decoded, e.g. a msgpack cell), entropy and
    /// generic-pattern matchers fire on garbage, so keep only high-confidence, specific-format matches there
    /// (a real `ghp_…`/`sk-ant-…` survives; a random high-entropy run inside a blob does not). A secret that only
    /// resolves as a generic/keyed medium match is dropped in these regions. Reliable text regions keep every match.
    static func keep(_ match: SecretMatch, in region: ContentRegion) -> Bool {
        region.offsetsReliable || match.confidence == .high
    }

    public func scan(installation: AgentInstallation, options: ScanOptions = ScanOptions()) async throws -> ScanReport {
        let started = Date()
        let (stores, storeGaps) = try await adapter.enumerateStores(installation: installation)
        var report = ScanReport(installation: installation, stores: stores, gaps: storeGaps, secrets: [],
                                occurrences: [], activeArtifacts: [:], artifactsScanned: 0, bytesExamined: 0,
                                startedAt: started, finishedAt: started)
        var identities: [SecretFingerprint: SecretIdentity] = [:]

        for store in stores where store.present && options.tiers.contains(store.tier) {
            let page = try await adapter.enumerateArtifacts(store: store, cursor: nil)
            report.gaps.append(contentsOf: page.gaps)
            for artifact in page.artifacts {
                let extracted: ExtractedContent
                do {
                    extracted = try await adapter.extractScannableContent(artifact: artifact)
                } catch {
                    report.gaps.append(CoverageGap(adapterID: adapter.id, storeID: store.id, path: artifact.url.path,
                                                   reason: .unreadable(error: String(describing: error))))
                    continue
                }
                report.artifactsScanned += 1
                report.bytesExamined += extracted.bytesExamined
                report.gaps.append(contentsOf: extracted.gaps)

                // Overlapping text chunks can report the same match twice; dedupe on (record, offset). The record
                // matters because SQLite cells all start at offset 0.
                var seen = Set<String>()
                var foundAny = false
                for region in extracted.regions {
                    // Highest confidence first so when a specific rule and the generic rule hit the same span, the
                    // per-offset dedup keeps the specific one (e.g. awsSecretAccessKey over genericSecret).
                    for match in scanner.scan(region.text).sorted(by: { $0.confidence > $1.confidence }) {
                        if Self.isExpiredJWT(match) { continue }
                        if !Self.keep(match, in: region) { continue }
                        let serialized = region.serializedRange(for: match.range)
                        guard seen.insert("\(region.locator)|\(serialized.lowerBound)").inserted else { continue }
                        foundAny = true
                        let fp = fingerprinter.fingerprint(namespace: match.namespace, canonical: match.canonical)
                        let now = Date()
                        var identity = identities[fp] ?? SecretIdentity(
                            fingerprint: fp, kind: match.kind, label: match.label, maskedDisplay: match.maskedDisplay,
                            confidence: match.confidence, firstSeen: now, lastSeen: now)
                        identity.lastSeen = now
                        identity.confidence = max(identity.confidence, match.confidence)
                        identities[fp] = identity

                        report.occurrences.append(SecretOccurrence(
                            secretID: identity.id, fingerprint: fp, adapterID: adapter.id, storeID: store.id,
                            artifactURL: artifact.url, fileIdentity: artifact.identity,
                            sessionID: artifact.sessionID, projectPath: artifact.projectPath,
                            recordLocator: region.locator, serializedByteRange: serialized,
                            feasibility: region.feasibility(for: match.range), discoveredAt: now))
                    }
                }
                if foundAny, case let .active(reason) = await adapter.activeState(artifact: artifact) {
                    report.activeArtifacts[artifact.url] = reason
                }
            }
        }
        report.secrets = identities.values.sorted { a, b in
            if a.confidence != b.confidence { return a.confidence > b.confidence }
            return a.alias < b.alias
        }
        report.finishedAt = Date()
        return report
    }

    /// Scans one artifact incrementally: extracts only what is new since `cursor`, detects secrets, and
    /// returns raw findings plus the cursor to persist. Identity merging across artifacts is the caller's job.
    public func rescanArtifact(_ artifact: Artifact, cursor: ScanCursor?) async throws -> ArtifactDelta {
        let ex = try await adapter.extractDelta(artifact: artifact, from: cursor)
        var findings: [RawFinding] = []
        var seen = Set<String>()
        for region in ex.content.regions {
            for match in scanner.scan(region.text).sorted(by: { $0.confidence > $1.confidence }) {
                if Self.isExpiredJWT(match) { continue }
                if !Self.keep(match, in: region) { continue }
                let serialized = region.serializedRange(for: match.range)
                guard seen.insert("\(region.locator)|\(serialized.lowerBound)").inserted else { continue }
                findings.append(RawFinding(
                    fingerprint: fingerprinter.fingerprint(namespace: match.namespace, canonical: match.canonical),
                    kind: match.kind, label: match.label, maskedDisplay: match.maskedDisplay,
                    confidence: match.confidence, adapterID: adapter.id, storeID: artifact.storeID,
                    artifactURL: artifact.url, fileIdentity: ex.newCursor.fileIdentity,
                    sessionID: artifact.sessionID, projectPath: artifact.projectPath,
                    recordLocator: region.locator, serializedByteRange: serialized,
                    feasibility: region.feasibility(for: match.range)))
            }
        }
        return ArtifactDelta(findings: findings, gaps: ex.content.gaps, bytesExamined: ex.content.bytesExamined,
                             newCursor: ex.newCursor, scannedFromOffset: ex.scannedFromOffset)
    }
}
