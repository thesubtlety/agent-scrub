import Foundation
import HistoryGuardCore
import SQLiteSupport

public struct CodexAdapter: AgentAdapter {
    public let id = CodexStores.adapterID
    public let displayName = "Codex"

    public var additionalRoots: [URL]
    public var includeDefaultRoots = true
    public var maxArtifactBytes: UInt64 = 1 << 30
    public var activityWindow: TimeInterval = 300
    /// Cells larger than this are skipped with a gap rather than decoded.
    public var maxCellBytes = 64 << 20
    let chunker = TextChunker()
    let walker = JSONStringWalker()
    let jsonl = JSONLReader()

    public init(additionalRoots: [URL] = [], includeDefaultRoots: Bool = true) {
        self.additionalRoots = additionalRoots
        self.includeDefaultRoots = includeDefaultRoots
    }

    // MARK: Discovery

    public func discoverInstallations() async -> [AgentInstallation] {
        let fm = FileManager.default
        var candidates: [URL] = []
        if includeDefaultRoots {
            if let env = ProcessInfo.processInfo.environment["CODEX_HOME"], !env.isEmpty { candidates.append(URL(fileURLWithPath: env)) }
            candidates.append(fm.homeDirectoryForCurrentUser.appendingPathComponent(".codex"))
        }
        candidates.append(contentsOf: additionalRoots)
        var seen = Set<String>()
        var out: [AgentInstallation] = []
        for c in candidates {
            let resolved = c.resolvingSymlinksInPath().standardizedFileURL
            guard seen.insert(resolved.path).inserted else { continue }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: resolved.path, isDirectory: &isDir), isDir.boolValue else { continue }
            out.append(AgentInstallation(adapterID: id, rootURL: resolved, version: detectVersion(root: resolved)))
        }
        return out
    }

    /// state_5.sqlite has a `cli_version` column on threads (migration 0005). Best effort, read-only.
    func detectVersion(root: URL) -> String? {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root.path) else { return nil }
        for n in names where n.hasPrefix("state_") && n.hasSuffix(".sqlite") {
            if let db = try? SQLiteDatabase(path: root.appendingPathComponent(n).path),
               let row = try? db.query("SELECT cli_version FROM threads WHERE cli_version <> '' ORDER BY updated_at DESC LIMIT 1").first,
               let v = row["cli_version"]?.text { return v }
        }
        return nil
    }

    // MARK: Stores

    public func enumerateStores(installation: AgentInstallation) async throws -> (stores: [StoreDescriptor], gaps: [CoverageGap]) {
        let root = installation.rootURL
        let entries = try FileManager.default.contentsOfDirectory(atPath: root.path)
        var locations: [StoreID: [URL]] = [:]
        var gaps: [CoverageGap] = []
        for entry in entries where !CodexStores.ignorableRootEntries.contains(entry) {
            if CodexStores.isSQLiteSidecar(entry) { continue }   // covered through the database itself
            if let k = CodexStores.store(claiming: entry) {
                locations[k.id, default: []].append(root.appendingPathComponent(entry))
            } else {
                gaps.append(CoverageGap(adapterID: id, storeID: nil, path: root.appendingPathComponent(entry).path, reason: .unknownStore))
            }
        }
        var stores: [StoreDescriptor] = []
        for k in CodexStores.known {
            let locs = (locations[k.id] ?? []).sorted { $0.path < $1.path }
            var schema: SchemaStatus = .notApplicable
            var caps: StoreCapabilities = k.tier == .excluded ? [] : [.detect, .verify, .redactWhenInactive]
            if k.entries.contains(where: { $0.hasSuffix(".sqlite") }) {
                // Database stores: capabilities depend on whether we understand the schema.
                caps = k.tier == .excluded ? [] : [.detect, .verify]
                schema = locs.isEmpty ? .notApplicable : classify(databases: locs, store: k.id)
                if case .known = schema { caps.insert(.redactWhenInactive) }
            }
            stores.append(StoreDescriptor(id: k.id, adapterID: id, displayName: k.name, locations: locs, tier: k.tier,
                                          capabilities: caps, schema: schema, present: !locs.isEmpty, exclusionReason: k.exclusionReason))
        }
        return (stores, gaps)
    }

    /// Known when every expected table/column for the store exists; unknown otherwise (still scanned read-only).
    func classify(databases: [URL], store: StoreID) -> SchemaStatus {
        guard let specs = CodexStores.knownSchemas[store] else { return .unknown(detail: "no schema handler for \(store.rawValue)") }
        for url in databases {
            guard let db = try? SQLiteDatabase(path: url.path), let sig = try? db.schemaSignature() else {
                return .unknown(detail: "cannot open \(url.lastPathComponent)")
            }
            for spec in specs {
                guard let cols = sig[spec.table] else { continue } // optional tables (renamed across migrations)
                let names = Set(cols.map { String($0.prefix(while: { $0 != ":" })) })
                for c in spec.columns + spec.json where !names.contains(c) {
                    // A column missing from a known table is fine (older migration); an unexpected table shape is not.
                    _ = c
                }
            }
            let expectedTables = Set(specs.map(\.table))
            if expectedTables.isDisjoint(with: sig.keys) {
                return .unknown(detail: "\(url.lastPathComponent) has none of the expected tables \(expectedTables.sorted())")
            }
        }
        return .known(version: CodexStores.schemaVersion)
    }

    // MARK: Artifacts

    public func enumerateArtifacts(store: StoreDescriptor, cursor: ScanCursor?) async throws -> ArtifactPage {
        var artifacts: [Artifact] = []
        var gaps: [CoverageGap] = []
        let fm = FileManager.default
        for location in store.locations {
            let rv = try location.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if rv.isSymbolicLink == true {
                gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: location.path,
                                        reason: .skippedSymlink(target: (try? fm.destinationOfSymbolicLink(atPath: location.path)) ?? "?")))
                continue
            }
            if rv.isDirectory != true {
                try classify(file: location, store: store, into: &artifacts, gaps: &gaps); continue
            }
            guard let e = fm.enumerator(at: location, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: []) else { continue }
            // nextObject() rather than `for case ... in e`: NSEnumerator's Sequence conformance is
            // unavailable in async contexts on the macOS toolchain, and skipDescendants() still works here.
            while let url = e.nextObject() as? URL {
                let v = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if v.isSymbolicLink == true {
                    e.skipDescendants()
                    gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path,
                                            reason: .skippedSymlink(target: (try? fm.destinationOfSymbolicLink(atPath: url.path)) ?? "?")))
                    continue
                }
                if v.isDirectory == true { continue }
                if store.id == CodexStores.rollouts || store.id == CodexStores.archivedRollouts {
                    // Only rollout-*.jsonl is conversation; anything else under sessions/ is unknown.
                    guard url.lastPathComponent.hasPrefix("rollout-"), url.pathExtension == "jsonl" else {
                        gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path, reason: .unknownStore)); continue
                    }
                }
                try classify(file: url, store: store, into: &artifacts, gaps: &gaps)
            }
        }
        return ArtifactPage(artifacts: artifacts, gaps: gaps)
    }

    /// `rollout-{timestamp}-{thread_id}.jsonl`; the thread id is the trailing UUID (optionally `_rolloutId`).
    public static func threadID(fromRolloutName name: String) -> String? {
        guard name.hasPrefix("rollout-"), name.hasSuffix(".jsonl") else { return nil }
        let core = name.dropFirst("rollout-".count).dropLast(".jsonl".count)
        let tail = core.split(separator: "_").first.map(String.init) ?? String(core)
        guard tail.count >= 36 else { return nil }
        let candidate = String(tail.suffix(36))
        return UUID(uuidString: candidate) != nil ? candidate.lowercased() : nil
    }

    func classify(file url: URL, store: StoreDescriptor, into artifacts: inout [Artifact], gaps: inout [CoverageGap]) throws {
        let name = url.lastPathComponent
        if CodexStores.isSQLiteSidecar(name) { return }
        let identity = try FileIdentity.read(at: url)
        if identity.size > maxArtifactBytes {
            gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path, reason: .oversizeArtifact(bytes: identity.size, limit: maxArtifactBytes)))
            return
        }
        let kind: ArtifactKind
        if name.hasSuffix(".sqlite") { kind = .sqlite }
        else if name.contains(".jsonl") { kind = .jsonl }
        else if url.pathExtension == "json" { kind = .json }
        else if isBinary(url) { kind = .binary }
        else { kind = .plainText }
        artifacts.append(Artifact(url: url, storeID: store.id, kind: kind, identity: identity,
                                  sessionID: Self.threadID(fromRolloutName: name), projectPath: nil))
    }

    func isBinary(_ url: URL) -> Bool {
        guard let fh = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? fh.close() }
        return ((try? fh.read(upToCount: 8192)) ?? Data()).contains(0)
    }

    // MARK: Extraction

    public func extractScannableContent(artifact: Artifact) async throws -> ExtractedContent {
        switch artifact.kind {
        case .binary:
            return ExtractedContent(regions: [], gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: .binaryArtifact)], bytesExamined: 0)
        case .jsonl: return try extractJSONL(artifact)
        case .json: return try extractJSON(artifact)
        case .plainText: return try extractPlainText(artifact)
        case .sqlite: return try extractSQLite(artifact)
        }
    }

    func extractJSONL(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        var gaps: [CoverageGap] = []
        let summary = try jsonl.forEachLine(at: artifact.url) { line in
            if line.bytes.isEmpty { return }
            do {
                for s in try walker.strings(in: line.bytes) {
                    regions.append(ContentRegion(text: s.text, locator: .jsonlRecord(line: line.index, lineOffset: line.offset, pointer: s.pointer),
                                                 baseOffset: line.offset + s.bodyRange.lowerBound,
                                                 offsetMap: s.offsetMap.map { $0.map { $0 + line.offset } }, hasEscapes: s.hasEscapes))
                }
            } catch {
                let reason: CoverageGap.Reason = line.isTruncatedTail ? .truncatedTail(line: line.index) : .corruptRecord(line: line.index, detail: String(describing: error))
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: reason))
                regions.append(rawRegion(line.bytes, offset: line.offset, locator: .jsonlRecord(line: line.index, lineOffset: line.offset, pointer: "")))
            }
        }
        for skipped in summary.skippedOversize {
            gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                    reason: .oversizeRecord(line: skipped.line, offset: skipped.offset, limit: jsonl.maxRecordBytes)))
        }
        return ExtractedContent(regions: regions, gaps: gaps, bytesExamined: UInt64(summary.bytesRead))
    }

    func extractJSON(_ artifact: Artifact) throws -> ExtractedContent {
        let data = try Data(contentsOf: artifact.url)
        do {
            let regions = try walker.strings(in: data).map { s in
                ContentRegion(text: s.text, locator: .jsonDocument(pointer: s.pointer), baseOffset: s.bodyRange.lowerBound, offsetMap: s.offsetMap, hasEscapes: s.hasEscapes)
            }
            return ExtractedContent(regions: regions, gaps: [], bytesExamined: UInt64(data.count))
        } catch {
            return ExtractedContent(regions: [rawRegion(Array(data), offset: 0, locator: .plainFile)],
                                    gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: .corruptRecord(line: 0, detail: String(describing: error)))],
                                    bytesExamined: UInt64(data.count))
        }
    }

    func extractPlainText(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        let bytes = try chunker.forEachChunk(at: artifact.url) { regions.append(rawRegion($0.bytes, offset: $0.offset, locator: .plainFile)) }
        return ExtractedContent(regions: regions, gaps: [], bytesExamined: UInt64(bytes))
    }

    func rawRegion(_ bytes: [UInt8], offset: Int, locator: RecordLocator) -> ContentRegion {
        let text = String(decoding: bytes, as: UTF8.self)
        return ContentRegion(text: text, locator: locator, baseOffset: offset, offsetMap: nil, hasEscapes: false, offsetsReliable: text.utf8.count == bytes.count)
    }

    /// Reads every text cell of the known content columns (or, for an unknown schema, every TEXT column of every
    /// table) through the SQLite API, so WAL content is included. Cell offsets are relative to the cell's bytes.
    func extractSQLite(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        var gaps: [CoverageGap] = []
        var bytes: UInt64 = 0
        guard let db = SQLiteDatabase.openForReading(path: artifact.url.path) else {
            return ExtractedContent(regions: [], gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: .unreadable(error: "cannot open database"))], bytesExamined: 0)
        }
        // Read-only fallback while a live WAL holds frames means uncheckpointed rows weren't scanned — report it.
        if db.isReadOnly, SQLiteDatabase.hasLiveWAL(forDBAt: artifact.url.path) {
            gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                    reason: .unreadable(error: "opened read-only; live WAL data not scanned")))
        }
        let signature = try db.schemaSignature()
        var plan: [(table: String, column: String, json: Bool)] = []
        if let specs = CodexStores.knownSchemas[artifact.storeID] {
            for spec in specs {
                guard let cols = signature[spec.table] else { continue }
                let present = Set(cols.map { String($0.prefix(while: { $0 != ":" })) })
                for c in spec.columns where present.contains(c) { plan.append((spec.table, c, false)) }
                for c in spec.json where present.contains(c) { plan.append((spec.table, c, true)) }
            }
            // Unknown extra tables in a known database are reported so they can be reviewed, and scanned generically.
            let knownTables = Set(specs.map(\.table))
            for (table, cols) in signature where !knownTables.contains(table) && !table.hasPrefix("_sqlx") {
                let textCols = cols.filter { $0.hasSuffix(":TEXT") }.map { String($0.prefix(while: { $0 != ":" })) }
                if !textCols.isEmpty {
                    gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                            reason: .unsupportedSchema(detail: "table \(table) is not covered by the schema handler; scanned read-only")))
                    for c in textCols { plan.append((table, c, false)) }
                }
            }
        } else {
            gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                    reason: .unsupportedSchema(detail: "no schema handler; all TEXT columns scanned read-only")))
            for (table, cols) in signature where !table.hasPrefix("_sqlx") {
                for c in cols where c.hasSuffix(":TEXT") { plan.append((table, String(c.prefix(while: { $0 != ":" })), false)) }
            }
        }

        for step in plan {
            let sql = "SELECT rowid AS __rowid, \(db.quoteIdentifier(step.column)) AS __cell FROM \(db.quoteIdentifier(step.table)) WHERE \(db.quoteIdentifier(step.column)) IS NOT NULL"
            do {
                try db.forEachRow(sql) { row in
                    guard let rowid = row["__rowid"]?.integer, let cell = row["__cell"]?.text, !cell.isEmpty else { return }
                    let cellBytes = Array(cell.utf8)
                    bytes += UInt64(cellBytes.count)
                    if cellBytes.count > maxCellBytes {
                        gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                                reason: .oversizeRecord(line: Int(rowid), offset: 0, limit: maxCellBytes)))
                        return
                    }
                    let locator = RecordLocator.sqliteCell(table: step.table, rowid: rowid, column: step.column)
                    if step.json, let strings = try? walker.strings(in: cellBytes) {
                        for s in strings {
                            regions.append(ContentRegion(text: s.text, locator: locator, baseOffset: s.bodyRange.lowerBound, offsetMap: s.offsetMap, hasEscapes: s.hasEscapes))
                        }
                    } else {
                        regions.append(ContentRegion(text: cell, locator: locator, baseOffset: 0, offsetMap: nil, hasEscapes: false))
                    }
                }
            } catch SQLiteError.busy {
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: .unreadable(error: "database busy while reading \(step.table).\(step.column)")))
            } catch {
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: .unreadable(error: "\(step.table).\(step.column): \(error)")))
            }
        }
        return ExtractedContent(regions: regions, gaps: gaps, bytesExamined: bytes)
    }

    // MARK: Activity

    public func activeState(artifact: Artifact) async -> ArtifactActivity {
        guard let root = rootContaining(artifact.url) else { return .unknown }
        if let thread = artifact.sessionID, writerLockHeld(root: root, threadID: thread) {
            return .active(reason: "Codex holds the writer lock for thread \(thread.prefix(8))")
        }
        if artifact.kind == .sqlite, SQLiteDatabase.hasLiveWAL(forDBAt: artifact.url.path),
           Date().timeIntervalSince(artifact.identity.modified) < activityWindow {
            return .active(reason: "database has a live WAL and changed \(Int(Date().timeIntervalSince(artifact.identity.modified)))s ago")
        }
        let age = Date().timeIntervalSince(artifact.identity.modified)
        if age < activityWindow, anyWriterLockHeld(root: root) {
            return .active(reason: "modified \(Int(age))s ago while a Codex writer lock is held")
        }
        return .inactive
    }

    func rootContaining(_ url: URL) -> URL? {
        var u = url.deletingLastPathComponent()
        let fm = FileManager.default
        while u.path != "/" {
            if fm.fileExists(atPath: u.appendingPathComponent("sessions").path) || fm.fileExists(atPath: u.appendingPathComponent("history.jsonl").path) { return u }
            u = u.deletingLastPathComponent()
        }
        return nil
    }

    /// Codex takes an exclusive flock on `thread-writer-locks/<thread>.lock` while it owns the rollout. A failed
    /// non-blocking flock means a live writer; the lock is released immediately either way.
    func writerLockHeld(root: URL, threadID: String) -> Bool {
        lockHeld(at: root.appendingPathComponent("thread-writer-locks/\(threadID).lock"))
    }

    func anyWriterLockHeld(root: URL) -> Bool {
        let dir = root.appendingPathComponent("thread-writer-locks")
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return false }
        return names.contains { $0.hasSuffix(".lock") && lockHeld(at: dir.appendingPathComponent($0)) }
    }

    func lockHeld(at url: URL) -> Bool {
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 { flock(fd, LOCK_UN); return false }
        return errno == EWOULDBLOCK
    }

    // MARK: Mutation

    public func redactionConstraint(for occurrence: SecretOccurrence, in store: StoreDescriptor) -> RedactionDeferral? {
        if store.tier == .excluded { return .storeReadOnly }
        if case .sqliteCell = occurrence.recordLocator {
            // Only databases whose schema this version understands are ever written.
            guard case .known = store.schema else { return .storeReadOnly }
        }
        return nil
    }

    /// Cells are addressed by (table, rowid, column); the range is within the cell's UTF-8 bytes.
    public func currentBytes(for occurrence: SecretOccurrence, before: Int, after: Int) throws -> (bytes: [UInt8], start: Int)? {
        guard case let .sqliteCell(table, rowid, column) = occurrence.recordLocator else {
            let range = occurrence.serializedByteRange
            let fh = try FileHandle(forReadingFrom: occurrence.artifactURL)
            defer { try? fh.close() }
            let start = max(0, range.lowerBound - before)
            try fh.seek(toOffset: UInt64(start))
            guard let data = try fh.read(upToCount: (range.upperBound + after) - start), data.count >= range.upperBound - start else { return nil }
            return (Array(data), start)
        }
        guard let db = SQLiteDatabase.openForReading(path: occurrence.artifactURL.path) else { return nil }
        guard let cell = try db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"]?.text else { return nil }
        let bytes = Array(cell.utf8)
        let range = occurrence.serializedByteRange
        guard range.upperBound <= bytes.count else { return nil }
        let start = max(0, range.lowerBound - before)
        return (Array(bytes[start..<min(bytes.count, range.upperBound + after)]), start)
    }

    public func rawContainerBytes(for occurrence: SecretOccurrence) throws -> [UInt8]? {
        guard case let .sqliteCell(table, rowid, column) = occurrence.recordLocator else {
            return Array(try Data(contentsOf: occurrence.artifactURL))
        }
        guard let db = SQLiteDatabase.openForReading(path: occurrence.artifactURL.path),
              let v = try db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"],
              let (bytes, _) = SQLiteCellRedactor.cellBytes(v) else { return nil }
        return bytes
    }

    public func apply(plan: RedactionPlan, verifyPreimage: @Sendable @escaping ([UInt8], RedactionTarget) -> Bool) async throws -> RedactionResult {
        var outcomes: [UUID: RedactionOutcome] = [:]
        var fileTargets: [RedactionTarget] = []
        var cellTargets: [RedactionTarget] = []
        for t in plan.targets {
            if case .sqliteCell = t.locator { cellTargets.append(t) } else { fileTargets.append(t) }
        }
        outcomes.merge(InPlaceRedactor(maxRecordBytes: jsonl.maxRecordBytes).apply(targets: fileTargets, verifyPreimage: verifyPreimage)) { a, _ in a }
        // Codex's content columns are JSON (per the schema); a cell in such a column must still parse after the
        // rewrite. The shared redactor handles TEXT and BLOB cells and the transaction/rollback/integrity checks.
        let policy = SQLiteCellRedactor.Policy(busyWriter: "Codex") { target, _, _ in
            guard case let .sqliteCell(table, _, column) = target.locator else { return false }
            return self.isJSONColumn(table: table, column: column, store: target.storeID)
        }
        outcomes.merge(SQLiteCellRedactor().apply(cellTargets, verifyPreimage: verifyPreimage, policy: policy)) { a, _ in a }
        return RedactionResult(outcomes: outcomes)
    }

    func isJSONColumn(table: String, column: String, store: StoreID) -> Bool {
        CodexStores.knownSchemas[store]?.contains { $0.table == table && $0.json.contains(column) } ?? false
    }
}
