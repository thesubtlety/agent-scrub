import Foundation
import HistoryGuardCore
import SecretDetection
import HistoryGuardDB

public struct RedactionSummary: Sendable {
    public let applied: Int
    public let deferred: Int
    public let failed: Int
    /// Copies of the secret still found after the re-verification reconcile.
    public let remaining: Int
    /// Why copies were deferred, e.g. ["in an active session": 3, "the value is escaped …": 1].
    public let deferredReasons: [String: Int]
    public var isVerifiedClean: Bool { remaining == 0 && failed == 0 }
    public init(applied: Int, deferred: Int, failed: Int, remaining: Int, deferredReasons: [String: Int] = [:]) {
        self.applied = applied; self.deferred = deferred; self.failed = failed
        self.remaining = remaining; self.deferredReasons = deferredReasons
    }
}

/// The resident monitor. Runs an initial sweep, applies deltas as files change, keeps per-artifact
/// cursors and the live findings index, and publishes `MonitorState`.
public actor MonitorService {
    struct Pair: Sendable { let adapter: any AgentAdapter; let installation: AgentInstallation }

    private let pairs: [Pair]
    private let scanner: SecretScanner
    private let fingerprinter: Fingerprinter
    private let state: StateStore
    private let changeSource: any FileChangeSource
    private let options: ScanOptions

    private var index = LiveFindingsIndex()
    private var storeStates: [MonitorState.StoreState] = []
    private var enumerationGaps: [CoverageGap] = []
    private var lastVerified: Date?
    private var inaccessible = false
    private var paused = false
    private var scanning = false
    private var lastEmitted: MonitorState = .empty
    private var lastProgressEmit = Date.distantPast
    private var consumeTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var reconciling = false
    private var reconcileRequested = false
    private var activeArtifactPaths: Set<String> = []
    private var autoRedactFingerprints: Set<SecretFingerprint> = []
    private var exclusions: Set<String> = []
    private var lifetimeCopiesRedacted = 0
    private var lifetimeSecretsRedacted = 0

    private let stateStream: AsyncStream<MonitorState>
    private let stateCont: AsyncStream<MonitorState>.Continuation
    public nonisolated var states: AsyncStream<MonitorState> { stateStream }
    public func currentState() -> MonitorState { lastEmitted }
    /// Recent audit events, read through the actor so the non-Sendable StateStore stays actor-owned.
    public func recentEvents(limit: Int) -> [AuditEvent] { (try? state.recentEvents(limit: limit)) ?? [] }

    /// Overwrite every supported copy of one secret in place, then reconcile to re-verify it is gone.
    /// The engine re-reads and re-checks each byte range before writing; active/unsupported copies are
    /// deferred, never silently rewritten.
    public func redact(fingerprint: SecretFingerprint, allowActive: Bool = false, allowBinaryForce: Bool = false) async -> RedactionSummary {
        // Hold off background reconciles for the duration so they don't interleave with the scoped scans below.
        let alreadyReconciling = reconciling
        reconciling = true
        defer {
            if !alreadyReconciling {
                reconciling = false
                if reconcileRequested { reconcileRequested = false; Task { [weak self] in await self?.reconcileAll() } }
            }
        }
        // Freshen just the files that hold this secret (forced full rescan) so plans use current byte ranges —
        // not a full sweep of every store.
        let targetPaths = Set(index.occurrences().filter { $0.fingerprint == fingerprint }.map { $0.artifactURL.path })
        await performReconcile(focus: targetPaths)
        var applied = 0, deferred = 0, failed = 0
        var deferredReasons: [String: Int] = [:]
        var rewritten = Set<String>()
        for pair in pairs {
            let adapter = pair.adapter
            let occs = index.occurrences().filter { $0.fingerprint == fingerprint && $0.adapterID == adapter.id }
            guard !occs.isEmpty else { continue }
            guard let enumerated = try? await adapter.enumerateStores(installation: pair.installation) else {
                failed += occs.count; continue
            }
            let report = ScanReport(
                installation: pair.installation, stores: enumerated.stores, gaps: [],
                secrets: index.identity(for: fingerprint).map { [$0] } ?? [], occurrences: occs,
                activeArtifacts: [:], artifactsScanned: 0, bytesExamined: 0, startedAt: Date(), finishedAt: Date())
            let engine = RedactionEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter)
            let plan = await engine.plan(report: report, fingerprints: [fingerprint],
                                         options: RedactionOptions(allowActiveArtifacts: allowActive,
                                                                   allowUnverifiedBinaryRewrite: allowBinaryForce,
                                                                   scanOptions: options))
            deferred += plan.deferred.count
            for (_, reason) in plan.deferred { deferredReasons[Self.deferralLabel(reason), default: 0] += 1 }
            for t in plan.targets { rewritten.insert(t.artifactURL.path) }
            if !plan.targets.isEmpty {
                if let result = try? await adapter.apply(plan: plan, verifyPreimage: engine.preimageVerifier()) {
                    applied += result.appliedCount
                    failed += result.failed.count
                    try? state.append(AuditEvent(ts: Date(), kind: "redaction.applied", adapterID: adapter.id.rawValue,
                        storeID: nil, fingerprintPrefix: String(fingerprint.hex.prefix(8)), artifactID: nil,
                        message: "Redacted \(result.appliedCount) cop\(result.appliedCount == 1 ? "y" : "ies")"))
                } else {
                    failed += plan.targets.count
                }
            }
        }
        // Independently re-verify: forced full rescan of just the rewritten files, then count what remains.
        await performReconcile(focus: rewritten)
        let remaining = index.occurrences().filter { $0.fingerprint == fingerprint }.count
        // Lifetime totals (persisted): copies overwritten, and secrets fully cleared.
        if applied > 0 {
            lifetimeCopiesRedacted += applied
            try? state.metaSet("lifetime_copies_redacted", String(lifetimeCopiesRedacted))
            if remaining == 0 {
                lifetimeSecretsRedacted += 1
                try? state.metaSet("lifetime_secrets_redacted", String(lifetimeSecretsRedacted))
            }
            emit()   // publish the new lifetime totals
        }
        return RedactionSummary(applied: applied, deferred: deferred, failed: failed, remaining: remaining,
                                deferredReasons: deferredReasons)
    }

    /// Live bytes around an occurrence, read through its owning adapter so SQLite cells are read from the cell
    /// (not the DB file at a cell-relative offset). Used by the detail view's context/reveal; nothing is stored.
    public func recordBytes(for occ: SecretOccurrence, before: Int, after: Int) -> (bytes: [UInt8], start: Int)? {
        guard let adapter = pairs.first(where: { $0.adapter.id == occ.adapterID })?.adapter else { return nil }
        return try? adapter.currentBytes(for: occ, before: before, after: after)
    }

    private static func deferralLabel(_ deferral: RedactionDeferral) -> String {
        switch deferral {
        case .artifactActive: "in an active session (will retry when it ends)"
        case .requiresSemanticRewrite: "the record isn't cleanly decodable (non-UTF-8), so it's left as-is"
        case .binaryRecordNeedsForce: "inside a binary record — use “Force-redact” to remove it"
        case .binaryRecordUnredactable: "its exact bytes weren't found uniquely in the binary record"
        case .storeReadOnly: "in a read-only store"
        case let .artifactChanged(d): d.isEmpty ? "the file changed since the scan" : "the file changed since the scan (\(d))"
        case .unreadable: "unreadable"
        }
    }

    public init(pairs: [(adapter: any AgentAdapter, installation: AgentInstallation)],
                scanner: SecretScanner, fingerprinter: Fingerprinter, state: StateStore,
                changeSource: any FileChangeSource, options: ScanOptions = ScanOptions()) {
        self.pairs = pairs.map { Pair(adapter: $0.adapter, installation: $0.installation) }
        self.scanner = scanner; self.fingerprinter = fingerprinter; self.state = state
        self.changeSource = changeSource; self.options = options
        var c: AsyncStream<MonitorState>.Continuation!
        stateStream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { c = $0 }
        stateCont = c
        // Persisted fingerprints are HMACs under the installation key. If that key changed (reinstall, lost or
        // regenerated Keychain item), stored findings can never match a live scan — drop them and rebuild.
        let keyProbe = fingerprinter.fingerprint(namespace: "__installation_key_probe__", canonical: Data()).hex
        let storedProbe = (try? state.metaGet("key_probe")) ?? nil
        if storedProbe != keyProbe {
            try? state.clearFindings()
            try? state.metaSet("key_probe", keyProbe)
        }
        lifetimeCopiesRedacted = Int((try? state.metaGet("lifetime_copies_redacted")) ?? nil ?? "") ?? 0
        lifetimeSecretsRedacted = Int((try? state.metaGet("lifetime_secrets_redacted")) ?? nil ?? "") ?? 0
        // Load previously persisted findings so a relaunch shows them instantly and rescans only changes.
        if let ids = try? state.loadIdentities(), let occ = try? state.loadOccurrencesByPath() {
            var byURL: [URL: [SecretOccurrence]] = [:]
            for (path, occs) in occ { byURL[URL(fileURLWithPath: path)] = occs }
            index.seed(identities: ids, occurrencesByArtifact: byURL)
        }
    }

    public func start() async {
        changeSource.start(roots: pairs.map { $0.installation.rootURL })
        await reconcileAll()
        let source = changeSource   // Sendable local; the Task never touches actor state directly
        consumeTask = Task { [weak self] in
            var last = Date()
            for await _ in source.batches {
                // Coalesce bursts from active AI sessions — don't re-reconcile more than ~every 3s.
                let gap = Date().timeIntervalSince(last)
                if gap < 3 { try? await Task.sleep(nanoseconds: UInt64((3 - gap) * 1_000_000_000)) }
                last = Date()
                await self?.reconcileAll()
            }
        }
        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 15 * 60 * 1_000_000_000)   // 15-min metadata reconcile (§18)
                if Task.isCancelled { break }
                await self?.reconcileAll()
            }
        }
    }

    public func stop() {
        paused = true
        consumeTask?.cancel()
        timerTask?.cancel()
        changeSource.stop()
        emit()
    }

    /// Single-flight guard: an actor await inside a reconcile would otherwise let a second reconcile
    /// interleave and double-count. Overlapping calls coalesce into one trailing run.
    public func reconcileAll() async {
        if reconciling { reconcileRequested = true; return }
        reconciling = true
        repeat {
            reconcileRequested = false
            await performReconcile()
        } while reconcileRequested
        reconciling = false
        await enforceAutoRedact()   // runs with the guard released so redact's own scans work normally
    }

    /// Folders (or files) the user excluded from scanning. Artifacts under these are skipped and their existing
    /// findings pruned on the next reconcile — the caller reconciles when it wants the change applied.
    public func setExclusions(_ paths: Set<String>) {
        exclusions = Set(paths.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path })
    }
    private func isExcluded(_ path: String) -> Bool {
        guard !exclusions.isEmpty else { return false }   // common case: no work
        let p = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        return exclusions.contains { p == $0 || p.hasPrefix($0 + "/") }
    }

    /// Fingerprints the user marked "Always redact". Pushed by the app whenever its policies change.
    public func setAutoRedact(_ fingerprints: Set<SecretFingerprint>) async {
        let added = !fingerprints.subtracting(autoRedactFingerprints).isEmpty
        autoRedactFingerprints = fingerprints
        if added { await enforceAutoRedact() }   // apply immediately to anything already on screen
    }

    /// Redact every always-redact secret that still has copies. Inactive files only (a live copy retries on the
    /// next scan once its session ends); each goes through the same verified, roll-back-on-failure engine.
    private func enforceAutoRedact() async {
        guard !autoRedactFingerprints.isEmpty else { return }
        let live = Set(index.occurrences().map(\.fingerprint))
        for fp in autoRedactFingerprints where live.contains(fp) {
            _ = await redact(fingerprint: fp, allowActive: false)
        }
    }

    /// Enumerate every installation's stores, apply deltas for changed artifacts, drop removed ones,
    /// and publish. Enumeration is a stat walk; content scanning is gated by cursors.
    /// With `focus`, only the named artifact paths are scanned (forced full, so the merge replaces rather than
    /// appends) and nothing is pruned — used by redaction to refresh just the affected files, not sweep everything.
    private func performReconcile(focus: Set<String>? = nil) async {
        // A focused (redaction) reconcile scans only a few files; it must not clobber the full scan's shared
        // coverage/store/accessibility state (which a concurrent background reconcile may be mid-way through
        // computing). Accumulate into locals and only commit them on a full reconcile.
        var localInaccessible = false
        var localGaps: [CoverageGap] = []
        var newStores: [MonitorState.StoreState] = []
        var toScan: [ScanItem] = []
        var seenPaths = Set<String>()
        let now = Date()

        // 1. Enumerate (a fast stat walk) and decide skip-vs-scan per artifact.
        for pair in pairs {
            let adapter = pair.adapter
            let result: (stores: [StoreDescriptor], gaps: [CoverageGap])
            do { result = try await adapter.enumerateStores(installation: pair.installation) }
            catch { localInaccessible = true; continue }
            localGaps += result.gaps

            for store in result.stores where store.present && options.tiers.contains(store.tier) {
                let page: ArtifactPage
                do { page = try await adapter.enumerateArtifacts(store: store, cursor: nil) }
                catch { localInaccessible = true; continue }
                localGaps += page.gaps
                newStores.append(MonitorState.StoreState(adapterID: adapter.id, storeID: store.id,
                    displayName: store.displayName, present: store.present, gapCount: page.gaps.count))

                for artifact in page.artifacts {
                    if isExcluded(artifact.url.path) { continue }   // skip; not added to seenPaths, so it's pruned
                    if let focus {
                        // Force a full rescan of just the targeted files (nil cursor → applyFull → replace).
                        if focus.contains(artifact.url.path) {
                            toScan.append(ScanItem(adapter: adapter, store: store, artifact: artifact, cursor: nil))
                        }
                        continue
                    }
                    seenPaths.insert(artifact.url.path)
                    let old = try? state.loadCursor(path: artifact.url.path)
                    // Unchanged file → its findings are already in the (persisted) index; don't rescan.
                    if let c = old, unchanged(c.fileIdentity, artifact.identity) { continue }
                    toScan.append(ScanItem(adapter: adapter, store: store, artifact: artifact, cursor: old))
                }
            }
        }
        // Only a full reconcile owns the coverage picture; a focused one leaves the last full scan's values intact.
        if focus == nil {
            inaccessible = localInaccessible
            enumerationGaps = localGaps
            storeStates = newStores
        }
        scanning = !toScan.isEmpty   // only show "scanning" when there's real work — a no-op reconcile shouldn't flicker
        emit()

        // 2. Scan recent material first so likely hits surface fast.
        toScan.sort { $0.artifact.identity.modified > $1.artifact.identity.modified }

        // 3. Scan changed artifacts with bounded parallelism; merge each result serially on the actor.
        await scanChanged(toScan, now: now)

        // 4. Drop anything that no longer exists (skipped for a focused scan, which saw only some files).
        if focus == nil {
            for path in (try? state.allCursorPaths()) ?? [] where !seenPaths.contains(path) {
                index.remove(artifact: URL(fileURLWithPath: path))
                try? state.deleteOccurrences(path: path)
                try? state.deleteCursor(path: path)
            }
        }

        scanning = false
        if focus == nil { await pruneExpiredJWTs() }
        activeArtifactPaths = await computeActiveArtifacts()
        let gaps = enumerationGaps + index.findingGaps()
        let clean = index.occurrences().isEmpty && !gaps.contains(where: \.blocksCleanClaim) && !inaccessible
        if clean { lastVerified = now }
        emit()
    }

    /// Remove expired JWTs stored by an older scan: detection drops new ones, but occurrences seeded from the
    /// database aren't re-scanned, so they'd linger. Reads each JWT occurrence's current bytes to check `exp`.
    private func pruneExpiredJWTs() async {
        let jwtFps = Set(index.secrets().filter { $0.kind == .jwt }.map(\.fingerprint))
        guard !jwtFps.isEmpty else { return }
        var expired = Set<SecretFingerprint>()
        let byAdapter = Dictionary(grouping: index.occurrences().filter { jwtFps.contains($0.fingerprint) },
                                   by: { $0.adapterID })
        for (adapterID, group) in byAdapter {
            guard let adapter = pairs.first(where: { $0.adapter.id == adapterID })?.adapter else { continue }
            for o in group where !expired.contains(o.fingerprint) {
                if let (bytes, _) = try? adapter.currentBytes(for: o, before: 0, after: 0),
                   JWTInspect.isExpired(String(decoding: bytes, as: UTF8.self)) {
                    expired.insert(o.fingerprint)
                }
            }
        }
        let affected = index.removeFingerprints(expired)
        for url in affected { try? state.saveOccurrences(path: url.path, index.occurrences(forArtifact: url)) }
    }

    /// Which artifacts holding findings are in an active session right now, for the "live" badge. An adapter
    /// reports active when the file was written recently while that agent's process is running.
    private func computeActiveArtifacts() async -> Set<String> {
        var active = Set<String>()
        let byAdapter = Dictionary(grouping: index.occurrences(), by: { $0.adapterID })
        for (adapterID, occs) in byAdapter {
            guard let adapter = pairs.first(where: { $0.adapter.id == adapterID })?.adapter else { continue }
            var seen = Set<URL>()
            for occ in occs where seen.insert(occ.artifactURL).inserted {
                guard let identity = try? FileIdentity.read(at: occ.artifactURL) else { continue }
                let kind: ArtifactKind = occ.artifactURL.lastPathComponent.contains(".jsonl") ? .jsonl
                    : (occ.artifactURL.pathExtension == "json" ? .json : .plainText)
                let artifact = Artifact(url: occ.artifactURL, storeID: occ.storeID, kind: kind, identity: identity)
                if case .active = await adapter.activeState(artifact: artifact) { active.insert(occ.artifactURL.path) }
            }
        }
        return active
    }

    private struct ScanItem: Sendable {
        let adapter: any AgentAdapter
        let store: StoreDescriptor
        let artifact: Artifact
        let cursor: ScanCursor?
    }
    private struct ScanResult: Sendable {
        let item: ScanItem
        let delta: ArtifactDelta?
    }

    private func unchanged(_ a: FileIdentity, _ b: FileIdentity) -> Bool {
        a.device == b.device && a.inode == b.inode && a.size == b.size && a.modified == b.modified
    }

    /// Scans changed artifacts off the actor with bounded width; merges each result back on the actor.
    /// Scanning is CPU-bound and runs in parallel; index and DB writes stay serial on the actor.
    private func scanChanged(_ items: [ScanItem], now: Date) async {
        guard !items.isEmpty else { return }
        let scanner = self.scanner
        let fingerprinter = self.fingerprinter
        let scanOne: @Sendable (ScanItem) async -> ScanResult = { item in
            let engine = ScanEngine(adapter: item.adapter, scanner: scanner, fingerprinter: fingerprinter)
            let delta = try? await engine.rescanArtifact(item.artifact, cursor: item.cursor)
            return ScanResult(item: item, delta: delta)
        }
        let width = min(4, items.count)
        await withTaskGroup(of: ScanResult.self) { group in
            var it = items.makeIterator()
            for _ in 0..<width { if let item = it.next() { group.addTask { await scanOne(item) } } }
            while let result = await group.next() {
                merge(result, now: now)
                if let item = it.next() { group.addTask { await scanOne(item) } }
            }
        }
    }

    private func merge(_ result: ScanResult, now: Date) {
        guard let delta = result.delta else { inaccessible = true; return }
        let url = result.item.artifact.url
        let adapter = result.item.adapter
        let store = result.item.store
        // Audit-log only genuinely new secrets (checked before the index is mutated), once each — not a
        // line per rescan of an already-known secret.
        var newlyDiscovered: [RawFinding] = []
        var seenFP = Set<SecretFingerprint>()
        for f in delta.findings where index.identity(for: f.fingerprint) == nil && seenFP.insert(f.fingerprint).inserted {
            newlyDiscovered.append(f)
        }

        if delta.scannedFromOffset == 0 {
            index.applyFull(artifact: url, delta: delta, now: now)       // full scan → replace
        } else {
            index.applyDeltaAppend(artifact: url, delta: delta, now: now) // tail → append
        }
        try? state.saveCursor(path: url.path, adapterID: adapter.id.rawValue, storeID: store.id.rawValue, delta.newCursor)
        try? state.saveOccurrences(path: url.path, index.occurrences(forArtifact: url))
        for fp in Set(delta.findings.map(\.fingerprint)) {
            if let identity = index.identity(for: fp) { try? state.saveIdentity(identity) }
        }
        for f in newlyDiscovered {
            try? state.append(AuditEvent(ts: now, kind: "finding.discovered", adapterID: adapter.id.rawValue,
                storeID: store.id.rawValue, fingerprintPrefix: String(f.fingerprint.hex.prefix(8)),
                artifactID: url.path, message: "Discovered \(f.label)"))
        }
        emitProgress()   // coalesced: stream findings in without a snapshot per file
    }

    /// Progressive emit during a scan, coalesced so the UI updates a few times a second, not per file.
    /// The unthrottled emit() at the end of the reconcile always publishes the final state.
    private func emitProgress() {
        let now = Date()
        guard now.timeIntervalSince(lastProgressEmit) > 0.7 else { return }
        lastProgressEmit = now
        emit()
    }

    private func emit() {
        let gaps = enumerationGaps + index.findingGaps()
        let occ = index.occurrences()
        // Status reflects findings/coverage and stays put across incremental rescans — it must not flip to
        // gray every time a scan runs, or the menu bar icon flickers on every file change.
        let status: MonitorState.Status
        if paused { status = .gray }
        else if inaccessible { status = .red }
        else if !occ.isEmpty || gaps.contains(where: \.blocksCleanClaim) { status = .yellow }
        else if lastVerified != nil { status = .green }
        else { status = .gray }   // initial: nothing found yet and no verified-clean sweep
        let snapshot = MonitorState(status: status, secrets: index.secrets(), occurrences: occ,
            gaps: gaps, stores: storeStates, lastVerified: lastVerified, scanning: scanning,
            activeArtifacts: activeArtifactPaths,
            lifetimeCopiesRedacted: lifetimeCopiesRedacted, lifetimeSecretsRedacted: lifetimeSecretsRedacted)
        lastEmitted = snapshot
        stateCont.yield(snapshot)
    }
}
