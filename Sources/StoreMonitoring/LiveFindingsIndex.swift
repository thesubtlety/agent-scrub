import Foundation
import HistoryGuardCore
import SecretDetection

/// Cross-artifact merge of raw findings into stable identities and per-artifact occurrences.
/// Occurrences are partitioned by artifact URL: a delta appends to that artifact's list; a full
/// rescan replaces it; removal drops it.
public struct LiveFindingsIndex {
    private var identities: [SecretFingerprint: SecretIdentity] = [:]
    private var occByArtifact: [URL: [SecretOccurrence]] = [:]
    private var gapsByArtifact: [URL: [CoverageGap]] = [:]

    public init() {}

    /// Load a previously persisted index (from StateStore) so a relaunch shows findings without rescanning.
    public mutating func seed(identities: [SecretFingerprint: SecretIdentity],
                              occurrencesByArtifact: [URL: [SecretOccurrence]]) {
        self.identities = identities
        self.occByArtifact = occurrencesByArtifact
        pruneIdentities()
    }

    public func occurrences(forArtifact url: URL) -> [SecretOccurrence] { occByArtifact[url] ?? [] }
    public func identity(for fingerprint: SecretFingerprint) -> SecretIdentity? { identities[fingerprint] }

    public mutating func applyFull(artifact url: URL, delta: ArtifactDelta, now: Date) {
        occByArtifact[url] = delta.findings.map { occurrence(from: $0, now: now) }
        gapsByArtifact[url] = delta.gaps
        pruneIdentities()
    }

    public mutating func applyDeltaAppend(artifact url: URL, delta: ArtifactDelta, now: Date) {
        occByArtifact[url, default: []].append(contentsOf: delta.findings.map { occurrence(from: $0, now: now) })
        gapsByArtifact[url, default: []].append(contentsOf: delta.gaps)
    }

    public mutating func remove(artifact url: URL) {
        occByArtifact[url] = nil
        gapsByArtifact[url] = nil
        pruneIdentities()
    }

    /// Remove every occurrence of the given fingerprints (e.g. an expired JWT seeded from an older scan).
    /// Returns the artifact URLs that changed, so the caller can re-persist them.
    public mutating func removeFingerprints(_ fingerprints: Set<SecretFingerprint>) -> Set<URL> {
        guard !fingerprints.isEmpty else { return [] }
        var affected = Set<URL>()
        for (url, occs) in occByArtifact {
            let kept = occs.filter { !fingerprints.contains($0.fingerprint) }
            if kept.count != occs.count { occByArtifact[url] = kept; affected.insert(url) }
        }
        pruneIdentities()
        return affected
    }

    public func secrets() -> [SecretIdentity] {
        let live = Set(occurrences().map(\.fingerprint))
        return identities.values.filter { live.contains($0.fingerprint) }
            .sorted { $0.confidence != $1.confidence ? $0.confidence > $1.confidence : $0.alias < $1.alias }
    }
    public func occurrences() -> [SecretOccurrence] { occByArtifact.values.flatMap { $0 } }
    public func findingGaps() -> [CoverageGap] { gapsByArtifact.values.flatMap { $0 } }

    private mutating func occurrence(from f: RawFinding, now: Date) -> SecretOccurrence {
        var identity = identities[f.fingerprint] ?? SecretIdentity(
            fingerprint: f.fingerprint, kind: f.kind, label: f.label, maskedDisplay: f.maskedDisplay,
            confidence: f.confidence, firstSeen: now, lastSeen: now)
        identity.lastSeen = now
        identity.confidence = max(identity.confidence, f.confidence)
        identities[f.fingerprint] = identity
        return SecretOccurrence(
            secretID: identity.id, fingerprint: f.fingerprint, adapterID: f.adapterID, storeID: f.storeID,
            artifactURL: f.artifactURL, fileIdentity: f.fileIdentity, sessionID: f.sessionID,
            projectPath: f.projectPath, recordLocator: f.recordLocator,
            serializedByteRange: f.serializedByteRange, feasibility: f.feasibility, discoveredAt: now)
    }

    private mutating func pruneIdentities() {
        let live = Set(occurrences().map(\.fingerprint))
        identities = identities.filter { live.contains($0.key) }
    }
}
