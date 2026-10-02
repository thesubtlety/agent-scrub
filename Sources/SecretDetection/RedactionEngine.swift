import Foundation
import HistoryGuardCore

public struct RedactionOptions: Sendable {
    /// Overwrite ranges inside artifacts that look active. Off by default: the spec waits for the session to end.
    public var allowActiveArtifacts = false
    /// Redact a secret inside a record whose decoded byte offsets can't be trusted (a binary/non-UTF-8 cell such
    /// as Cursor's msgpack blobs) by overwriting its exact bytes in place, same length. Off by default and meant
    /// to be a deliberate per-secret choice: it keeps the record the same size and the DB valid, but unlike a text
    /// record we can't re-parse the binary afterwards to confirm its structure.
    public var allowUnverifiedBinaryRewrite = false
    public var scanOptions = ScanOptions()
    public init(allowActiveArtifacts: Bool = false, allowUnverifiedBinaryRewrite: Bool = false, scanOptions: ScanOptions = ScanOptions()) {
        self.allowActiveArtifacts = allowActiveArtifacts
        self.allowUnverifiedBinaryRewrite = allowUnverifiedBinaryRewrite
        self.scanOptions = scanOptions
    }
}

/// Plans and drives in-place redaction. Planning re-reads and re-scans every byte range so a stale report can
/// never cause a write; applying is delegated to the adapter, which re-checks again immediately before writing.
public struct RedactionEngine: Sendable {
    public let adapter: any AgentAdapter
    public let scanner: SecretScanner
    public let fingerprinter: Fingerprinter

    /// Identifies one detected match within an artifact. The serialized byte range is absolute and unique for
    /// file-backed records (JSONL/JSON/plain); it is cell-relative for SQLite, so `cell` disambiguates those.
    /// Deliberately excludes the record's line index: an incremental rescan numbers lines from the delta start,
    /// so the same record can carry different line indices in different scans.
    struct MatchKey: Hashable { let cell: String?; let range: Range<Int> }

    private static func cellDiscriminator(_ locator: RecordLocator) -> String? {
        if case let .sqliteCell(table, rowid, column) = locator { return "\(table)|\(rowid)|\(column)" }
        return nil
    }

    public init(adapter: any AgentAdapter, scanner: SecretScanner, fingerprinter: Fingerprinter) {
        self.adapter = adapter
        self.scanner = scanner
        self.fingerprinter = fingerprinter
    }

    public func plan(report: ScanReport, fingerprints: Set<SecretFingerprint>, options: RedactionOptions = RedactionOptions()) async -> RedactionPlan {
        var targets: [RedactionTarget] = []
        var deferred: [UUID: RedactionDeferral] = [:]
        let stores = Dictionary(uniqueKeysWithValues: report.stores.map { ($0.id, $0) })
        let secrets = Dictionary(uniqueKeysWithValues: report.secrets.map { ($0.id, $0) })
        // One decoded re-extraction per artifact, reused across its occurrences (see `freshMatches`).
        var freshByArtifact: [URL: [MatchKey: Set<SecretFingerprint>]] = [:]

        for occ in report.occurrences where fingerprints.contains(occ.fingerprint) {
            guard let store = stores[occ.storeID], let secret = secrets[occ.secretID] else {
                deferred[occ.id] = .artifactChanged(detail: stores[occ.storeID] == nil ? "store absent from report" : "secret id absent from report"); continue
            }
            if !store.capabilities.contains(.redactWhenInactive) { deferred[occ.id] = .storeReadOnly; continue }
            if let veto = adapter.redactionConstraint(for: occ, in: store) { deferred[occ.id] = veto; continue }

            let editKind = occ.feasibility.editKind
            if editKind == .notRedactable { deferred[occ.id] = .requiresSemanticRewrite; continue }
            // A raw-byte rewrite overwrites the secret's exact bytes inside a record we can't re-parse, so it is
            // only attempted when the caller explicitly opts in; otherwise flag it for the UI's per-item force action.
            if editKind == .rawByteSameLength, !options.allowUnverifiedBinaryRewrite {
                deferred[occ.id] = .binaryRecordNeedsForce; continue
            }

            let identity: FileIdentity
            do { identity = try FileIdentity.read(at: occ.artifactURL) } catch { deferred[occ.id] = .unreadable(String(describing: error)); continue }
            if let want = occ.fileIdentity.inode, let have = identity.inode, want != have { deferred[occ.id] = .artifactChanged(detail: "inode \(want) → \(have)"); continue }
            let isCell: Bool = { if case .sqliteCell = occ.recordLocator { return true }; return false }()
            // Offset-based paths need the file still large enough for the recorded range; the raw-byte path
            // re-searches the record, so that check doesn't apply to it.
            if editKind != .rawByteSameLength, !isCell, Int(identity.size) < occ.serializedByteRange.upperBound { deferred[occ.id] = .artifactChanged(detail: "size \(identity.size) < range end \(occ.serializedByteRange.upperBound)"); continue }

            let artifact = Artifact(url: occ.artifactURL, storeID: occ.storeID, kind: .plainText, identity: identity)
            if case let .active(reason) = await adapter.activeState(artifact: artifact) {
                // H1: a same-length overwrite (in place or raw-byte) is safe on a live append-only file or a
                // transactional cell, but a resize rewrites the whole file atomically and would drop the agent's
                // concurrent appends — never resize a live file.
                let sameLength = (editKind == .sameLengthInPlace || editKind == .rawByteSameLength)
                if !(options.allowActiveArtifacts && sameLength) { deferred[occ.id] = .artifactActive(reason: reason); continue }
            }

            if editKind == .rawByteSameLength {
                if let t = await rawByteTarget(for: occ, secret: secret, identity: identity) { targets.append(t) }
                else { deferred[occ.id] = .binaryRecordUnredactable }
                continue
            }

            // Re-confirm the same secret still sits at exactly this serialized range. Verification uses the same
            // decoded extraction as detection: re-scanning the raw serialized bytes mis-handles JSON escaping at
            // the match boundary (a closing quote is stored as \"), so a byte-clean secret would look "changed".
            let fresh: [MatchKey: Set<SecretFingerprint>]
            if let cached = freshByArtifact[occ.artifactURL] {
                fresh = cached
            } else if let m = await freshMatches(for: occ, identity: identity) {
                fresh = m; freshByArtifact[occ.artifactURL] = m
            } else {
                deferred[occ.id] = .unreadable("could not re-extract artifact"); continue
            }
            let key = MatchKey(cell: Self.cellDiscriminator(occ.recordLocator), range: occ.serializedByteRange)
            guard fresh[key]?.contains(occ.fingerprint) == true else {
                let want = occ.serializedByteRange
                let near = fresh.keys.filter { abs($0.range.lowerBound - want.lowerBound) < 300 }
                    .map { "\($0.range.lowerBound)..\($0.range.upperBound)" }.sorted().prefix(6).joined(separator: ",")
                let detail = fresh[key] == nil
                    ? "no match at \(want.lowerBound)..\(want.upperBound); nearby ranges [\(near)]; total fresh matches \(fresh.count)"
                    : "range matched but fingerprint differs at \(want.lowerBound)..\(want.upperBound)"
                deferred[occ.id] = .artifactChanged(detail: detail); continue
            }

            // Read exactly the serialized bytes for the preimage the apply step re-checks before it writes.
            guard let (raw, _) = try? adapter.currentBytes(for: occ, before: 0, after: 0),
                  raw.count == occ.serializedByteRange.count else {
                deferred[occ.id] = .unreadable("could not read range"); continue
            }
            // Byte-length-preserving → same-length padded marker, overwritten in place. Escaped value → the bare
            // marker (plain ASCII, valid unescaped inside a JSON string) spliced in, resizing the record.
            let replacement = editKind == .sameLengthInPlace
                ? Replacement.bytes(length: raw.count, kind: secret.kind, fingerprint: occ.fingerprint)
                : Array(Replacement.marker(kind: secret.kind, fingerprint: occ.fingerprint).utf8)
            targets.append(RedactionTarget(
                occurrenceID: occ.id, secretID: occ.secretID, fingerprint: occ.fingerprint, adapterID: occ.adapterID,
                storeID: occ.storeID, artifactURL: occ.artifactURL, expectedIdentity: identity, range: occ.serializedByteRange,
                preimage: fingerprinter.fingerprint(namespace: "preimage", canonical: Data(raw)),
                replacement: replacement,
                locator: occ.recordLocator))
        }
        return RedactionPlan(targets: targets, deferred: deferred)
    }

    /// Build a target that overwrites the secret's exact bytes in place, for a record whose decoded offsets can't
    /// be trusted (binary / invalid UTF-8). Recovers the exact secret text from a fresh scan, then finds it in the
    /// record's raw bytes — succeeding only on a single unambiguous occurrence, so we never guess which copy to hit.
    /// Same length, so the record's size and any length-prefixed framing (e.g. msgpack) stay valid.
    private func rawByteTarget(for occ: SecretOccurrence, secret: SecretIdentity, identity: FileIdentity) async -> RedactionTarget? {
        guard let plaintext = await freshPlaintext(for: occ, identity: identity) else { return nil }
        let needle = Array(plaintext.utf8)
        guard !needle.isEmpty, let container = try? adapter.rawContainerBytes(for: occ) else { return nil }
        let hits = Self.ranges(of: needle, in: container)
        guard hits.count == 1 else { return nil }   // 0 = gone/changed; >1 = ambiguous — refuse to guess
        let range = hits[0]
        return RedactionTarget(
            occurrenceID: occ.id, secretID: occ.secretID, fingerprint: occ.fingerprint, adapterID: occ.adapterID,
            storeID: occ.storeID, artifactURL: occ.artifactURL, expectedIdentity: identity, range: range,
            preimage: fingerprinter.fingerprint(namespace: "preimage", canonical: Data(container[range])),
            replacement: Replacement.bytes(length: range.count, kind: secret.kind, fingerprint: occ.fingerprint),
            locator: occ.recordLocator)
    }

    /// All non-overlapping byte ranges where `needle` occurs in `haystack`.
    static func ranges(of needle: [UInt8], in haystack: [UInt8]) -> [Range<Int>] {
        guard !needle.isEmpty, haystack.count >= needle.count else { return [] }
        var out: [Range<Int>] = []
        var i = 0
        let last = haystack.count - needle.count
        while i <= last {
            if Array(haystack[i..<(i + needle.count)]) == needle { out.append(i..<(i + needle.count)); i += needle.count }
            else { i += 1 }
        }
        return out
    }

    /// Re-scan one occurrence's record and return the exact matched text for its fingerprint (the raw ASCII the
    /// detector saw), or nil if it is no longer present. The match text equals its raw bytes for an ASCII secret,
    /// which is what makes a raw-byte search of the record reliable.
    private func freshPlaintext(for occ: SecretOccurrence, identity: FileIdentity) async -> String? {
        let artifact = Artifact(url: occ.artifactURL, storeID: occ.storeID,
                                kind: Self.artifactKind(for: occ.artifactURL, locator: occ.recordLocator), identity: identity)
        guard let content = try? await adapter.extractScannableContent(artifact: artifact) else { return nil }
        let want = Self.cellDiscriminator(occ.recordLocator)
        for region in content.regions where Self.cellDiscriminator(region.locator) == want {
            for m in scanner.scan(region.text)
            where fingerprinter.fingerprint(namespace: m.namespace, canonical: m.canonical) == occ.fingerprint {
                return m.plaintext
            }
        }
        return nil
    }

    /// Re-extract one artifact exactly as detection does (decoded regions) and index every match by its record
    /// and serialized byte range. Planning verifies against this, not a raw byte re-scan, so JSON escaping around
    /// a match boundary can't make a still-present secret look changed.
    private func freshMatches(for occ: SecretOccurrence, identity: FileIdentity) async -> [MatchKey: Set<SecretFingerprint>]? {
        let artifact = Artifact(url: occ.artifactURL, storeID: occ.storeID,
                                kind: Self.artifactKind(for: occ.artifactURL, locator: occ.recordLocator), identity: identity)
        guard let content = try? await adapter.extractScannableContent(artifact: artifact) else { return nil }
        var out: [MatchKey: Set<SecretFingerprint>] = [:]
        for region in content.regions {
            for match in scanner.scan(region.text) {
                let serialized = region.serializedRange(for: match.range)
                out[MatchKey(cell: Self.cellDiscriminator(region.locator), range: serialized), default: []]
                    .insert(fingerprinter.fingerprint(namespace: match.namespace, canonical: match.canonical))
            }
        }
        return out
    }

    /// Mirror the adapter's enumeration, which decides kind from the file name (not the locator, which can fall
    /// back to `.plainFile` on a parse failure and disagree with how detection extracted the file).
    private static func artifactKind(for url: URL, locator: RecordLocator) -> ArtifactKind {
        if case .sqliteCell = locator { return .sqlite }
        let name = url.lastPathComponent
        if name.contains(".jsonl") { return .jsonl }
        if url.pathExtension == "json" { return .json }
        return .plainText
    }

    /// Plan + apply for the given fingerprints against a fresh report.
    public func redact(report: ScanReport, fingerprints: Set<SecretFingerprint>, options: RedactionOptions = RedactionOptions()) async throws -> (plan: RedactionPlan, result: RedactionResult) {
        let plan = await self.plan(report: report, fingerprints: fingerprints, options: options)
        let result = try await adapter.apply(plan: plan, verifyPreimage: preimageVerifier())
        return (plan, result)
    }

    public func preimageVerifier() -> @Sendable ([UInt8], RedactionTarget) -> Bool {
        let fp = fingerprinter
        return { bytes, target in fp.fingerprint(namespace: "preimage", canonical: Data(bytes)) == target.preimage }
    }

    /// Independent verification: a full fresh scan, filtered to the fingerprints of interest.
    public func verify(installation: AgentInstallation, fingerprints: Set<SecretFingerprint>, scanOptions: ScanOptions = ScanOptions()) async throws -> [SecretFingerprint: VerificationResult] {
        let engine = ScanEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter)
        let report = try await engine.scan(installation: installation, options: scanOptions)
        let blocking = report.gaps.filter(\.blocksCleanClaim)
        var out: [SecretFingerprint: VerificationResult] = [:]
        for fp in fingerprints {
            out[fp] = VerificationResult(fingerprint: fp, scannedStores: report.scannedStoreIDs, skippedStores: blocking,
                                         occurrencesRemaining: report.occurrences.filter { $0.fingerprint == fp },
                                         completedAt: report.finishedAt)
        }
        return out
    }
}
