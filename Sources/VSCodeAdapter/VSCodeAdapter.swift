import Foundation
import HistoryGuardCore
import SQLiteSupport

/// Scans and redacts AI chat stored by VS Code and its forks: Cursor, GitHub Copilot Chat, Windsurf (Codeium) and
/// Sourcegraph Cody. Two shapes: JSON-in-SQLite cells (`state.vscdb` ItemTable/cursorDiskKV `value` blobs) and
/// per-session JSON files (Copilot `chatSessions/*.json`). Reuses the shared JSON walker, InPlaceRedactor (files)
/// and a CodexAdapter-style transactional cell rewrite (SQLite). Local-only; never touches non-chat editor state.
public struct VSCodeAdapter: AgentAdapter {
    public let id = VSCodeStores.adapterID
    public let displayName = "VS Code chat (Cursor / Copilot / Windsurf / Cody)"

    public var additionalRoots: [URL]
    public var includeDefaultRoots = true
    public var maxArtifactBytes: UInt64 = 256 << 20
    public var maxCellBytes = 16 << 20
    /// Files/DBs modified more recently than this count as possibly-live (no reliable per-editor process signal).
    public var activityWindow: TimeInterval = 300
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
            let appSupport = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
            for name in VSCodeStores.editorDirNames { candidates.append(appSupport.appendingPathComponent(name)) }
        }
        candidates.append(contentsOf: additionalRoots)

        var seen = Set<String>()
        var out: [AgentInstallation] = []
        for c in candidates {
            let resolved = c.resolvingSymlinksInPath().standardizedFileURL
            guard seen.insert(resolved.path).inserted else { continue }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: resolved.path, isDirectory: &isDir), isDir.boolValue else { continue }
            // Only a dir with a User/ subtree is an editor install (where chat lives).
            guard fm.fileExists(atPath: resolved.appendingPathComponent("User").path) else { continue }
            out.append(AgentInstallation(adapterID: id, rootURL: resolved, version: nil))
        }
        return out
    }

    // MARK: Stores

    public func enumerateStores(installation: AgentInstallation) async throws -> (stores: [StoreDescriptor], gaps: [CoverageGap]) {
        let fm = FileManager.default
        let user = installation.rootURL.appendingPathComponent("User")
        let globalStorage = user.appendingPathComponent("globalStorage")
        let workspaceStorage = user.appendingPathComponent("workspaceStorage")

        var globalLocs: [URL] = []
        let globalDB = globalStorage.appendingPathComponent("state.vscdb")
        if fm.fileExists(atPath: globalDB.path) { globalLocs.append(globalDB) }

        var workspaceDBLocs: [URL] = []
        var chatLocs: [URL] = []
        let emptyWindow = globalStorage.appendingPathComponent("emptyWindowChatSessions")
        if fm.fileExists(atPath: emptyWindow.path) { chatLocs.append(emptyWindow) }
        for hash in (try? fm.contentsOfDirectory(atPath: workspaceStorage.path)) ?? [] {
            let ws = workspaceStorage.appendingPathComponent(hash)
            let db = ws.appendingPathComponent("state.vscdb")
            if fm.fileExists(atPath: db.path) { workspaceDBLocs.append(db) }
            for sub in ["chatSessions", "chatEditingSessions"] {
                let d = ws.appendingPathComponent(sub)
                var isDir: ObjCBool = false
                if fm.fileExists(atPath: d.path, isDirectory: &isDir), isDir.boolValue { chatLocs.append(d) }
            }
        }

        let scannable: StoreCapabilities = [.detect, .verify, .redactWhenInactive]
        let stores: [StoreDescriptor] = [
            StoreDescriptor(id: VSCodeStores.globalDB, adapterID: id, displayName: "Global chat database",
                            locations: globalLocs, tier: .conversation, capabilities: scannable,
                            schema: .known(version: VSCodeStores.schemaVersion), present: !globalLocs.isEmpty),
            StoreDescriptor(id: VSCodeStores.workspaceDB, adapterID: id, displayName: "Per-workspace chat databases",
                            locations: workspaceDBLocs, tier: .conversation, capabilities: scannable,
                            schema: .known(version: VSCodeStores.schemaVersion), present: !workspaceDBLocs.isEmpty),
            StoreDescriptor(id: VSCodeStores.chatSessions, adapterID: id, displayName: "Chat session files",
                            locations: chatLocs, tier: .conversation, capabilities: scannable,
                            schema: .known(version: VSCodeStores.schemaVersion), present: !chatLocs.isEmpty),
            StoreDescriptor(id: VSCodeStores.other, adapterID: id, displayName: "Other editor data",
                            locations: [installation.rootURL], tier: .excluded, capabilities: [], present: true,
                            exclusionReason: "Caches, settings, extensions and non-chat state — enumerated, never scanned"),
        ]
        return (stores, [])
    }

    // MARK: Artifacts

    public func enumerateArtifacts(store: StoreDescriptor, cursor: ScanCursor?) async throws -> ArtifactPage {
        var artifacts: [Artifact] = []
        var gaps: [CoverageGap] = []
        let fm = FileManager.default
        switch store.id {
        case VSCodeStores.globalDB, VSCodeStores.workspaceDB:
            for db in store.locations { try classify(file: db, store: store, kind: .sqlite, into: &artifacts, gaps: &gaps) }
        case VSCodeStores.chatSessions:
            for dir in store.locations {
                guard let e = fm.enumerator(at: dir, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: []) else { continue }
                while let url = e.nextObject() as? URL {
                    let v = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                    if v.isSymbolicLink == true {
                        e.skipDescendants()
                        gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path,
                                                reason: .skippedSymlink(target: (try? fm.destinationOfSymbolicLink(atPath: url.path)) ?? "?")))
                        continue
                    }
                    if v.isDirectory == true { continue }
                    if url.pathExtension == "json" { try classify(file: url, store: store, kind: .json, into: &artifacts, gaps: &gaps) }
                }
            }
        default: break   // the excluded "other" store is never enumerated for artifacts
        }
        return ArtifactPage(artifacts: artifacts, gaps: gaps)
    }

    private func openForReading(_ path: String) throws -> SQLiteDatabase {
        guard let db = SQLiteDatabase.openForReading(path: path) else { throw SQLiteError.open("cannot open \(path)") }
        return db
    }

    func classify(file url: URL, store: StoreDescriptor, kind: ArtifactKind, into artifacts: inout [Artifact], gaps: inout [CoverageGap]) throws {
        var identity = try FileIdentity.read(at: url)
        if kind == .sqlite {
            // SQLite writes land in the `-wal` first and the main file's mtime/size may not change until a
            // checkpoint. Fold the WAL's mtime/size into the change-detection identity (keeping the main file's
            // device/inode) so a new secret is rescanned promptly instead of waiting for a checkpoint.
            let wal = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + "-wal")
            if let w = try? FileIdentity.read(at: wal), w.size > 32 {   // >32: real frames, not a bare header
                identity = FileIdentity(device: identity.device, inode: identity.inode,
                                        size: identity.size + w.size, modified: max(identity.modified, w.modified))
            }
        }
        if identity.size > maxArtifactBytes {
            gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path,
                                    reason: .oversizeArtifact(bytes: identity.size, limit: maxArtifactBytes)))
            return
        }
        // The workspace hash is a useful "where" label.
        let components = url.pathComponents
        let project: String? = components.firstIndex(of: "workspaceStorage").flatMap { i in
            i + 1 < components.count ? components[i + 1] : nil
        }
        artifacts.append(Artifact(url: url, storeID: store.id, kind: kind, identity: identity,
                                  sessionID: nil, projectPath: project))
    }

    // MARK: Content extraction

    public func extractScannableContent(artifact: Artifact) async throws -> ExtractedContent {
        switch artifact.kind {
        case .sqlite: return try extractDB(artifact)
        case .json: return try extractJSON(artifact)
        case .jsonl: return try extractJSON(artifact)   // unexpected here, but handle defensively
        case .plainText: return try extractPlainText(artifact)
        case .binary:
            return ExtractedContent(regions: [], gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID,
                                                                    path: artifact.url.path, reason: .binaryArtifact)],
                                    bytesExamined: 0)
        }
    }

    /// Chat rows out of ItemTable / cursorDiskKV. Each `value` is JSON (sometimes TEXT, sometimes BLOB); we extract
    /// every string value with the shared walker so secrets map to exact byte offsets inside the cell.
    func extractDB(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        var gaps: [CoverageGap] = []
        var bytes: UInt64 = 0
        let db: SQLiteDatabase
        do { db = try openForReading(artifact.url.path) } catch {
            return ExtractedContent(regions: [], gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID,
                                                                    path: artifact.url.path, reason: .unreadable(error: String(describing: error)))],
                                    bytesExamined: 0)
        }
        // If we could only open read-only (read-only mount / permissions) while a live WAL holds frames, those
        // uncheckpointed rows weren't scanned — report it rather than silently claim the DB is clean.
        if db.isReadOnly, SQLiteDatabase.hasLiveWAL(forDBAt: artifact.url.path) {
            gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                    reason: .unreadable(error: "opened read-only; live WAL data not scanned")))
        }
        let present = Set((try? db.tables()) ?? [])
        let clause = VSCodeStores.chatKeyGlobs.map { _ in "key GLOB ?" }.joined(separator: " OR ")
        let params = VSCodeStores.chatKeyGlobs.map { SQLiteValue.text($0) }
        for table in VSCodeStores.kvTables where present.contains(table) {
            let qt = db.quoteIdentifier(table)
            // cursorDiskKV is Cursor's dedicated chat/agent store (bubbles, composers, message context, code
            // diffs, checkpoints) — scan every row so no content key is missed. ItemTable is the shared settings
            // store, so filter it to chat-ish keys to avoid scanning the whole editor's settings.
            let scanAll = (table == "cursorDiskKV")
            let sql = scanAll
                ? "SELECT rowid AS __rowid, value AS __cell FROM \(qt) WHERE value IS NOT NULL"
                : "SELECT rowid AS __rowid, value AS __cell FROM \(qt) WHERE value IS NOT NULL AND (\(clause))"
            do {
                try db.forEachRow(sql, scanAll ? [] : params) { row in
                    guard let rowid = row["__rowid"]?.integer, let (cellBytes, _) = self.cellBytes(row["__cell"]),
                          !cellBytes.isEmpty else { return }
                    bytes += UInt64(cellBytes.count)
                    if cellBytes.count > self.maxCellBytes {
                        gaps.append(CoverageGap(adapterID: self.id, storeID: artifact.storeID, path: artifact.url.path,
                                                reason: .oversizeRecord(line: Int(rowid), offset: 0, limit: self.maxCellBytes)))
                        return
                    }
                    let locator = RecordLocator.sqliteCell(table: table, rowid: rowid, column: "value")
                    if let strings = try? self.walker.strings(in: cellBytes) {
                        for s in strings {
                            regions.append(ContentRegion(text: s.text, locator: locator, baseOffset: s.bodyRange.lowerBound,
                                                         offsetMap: s.offsetMap, hasEscapes: s.hasEscapes))
                        }
                    } else {
                        regions.append(self.rawRegion(cellBytes, offset: 0, locator: locator))
                    }
                }
            } catch SQLiteError.busy {
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                        reason: .unreadable(error: "database busy while reading \(table)")))
            } catch {
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                        reason: .unreadable(error: "\(table): \(error)")))
            }
        }
        return ExtractedContent(regions: regions, gaps: gaps, bytesExamined: bytes)
    }

    func extractJSON(_ artifact: Artifact) throws -> ExtractedContent {
        let data = try Data(contentsOf: artifact.url)
        do {
            let regions = try walker.strings(in: data).map { s in
                ContentRegion(text: s.text, locator: .jsonDocument(pointer: s.pointer), baseOffset: s.bodyRange.lowerBound,
                              offsetMap: s.offsetMap, hasEscapes: s.hasEscapes)
            }
            return ExtractedContent(regions: regions, gaps: [], bytesExamined: UInt64(data.count))
        } catch {
            let gap = CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                  reason: .corruptRecord(line: 0, detail: String(describing: error)))
            return ExtractedContent(regions: [rawRegion(Array(data), offset: 0, locator: .plainFile)],
                                    gaps: [gap], bytesExamined: UInt64(data.count))
        }
    }

    func extractPlainText(_ artifact: Artifact) throws -> ExtractedContent {
        let data = try Data(contentsOf: artifact.url)
        return ExtractedContent(regions: [rawRegion(Array(data), offset: 0, locator: .plainFile)], gaps: [],
                                bytesExamined: UInt64(data.count))
    }

    func rawRegion(_ bytes: [UInt8], offset: Int, locator: RecordLocator) -> ContentRegion {
        let text = String(decoding: bytes, as: UTF8.self)
        return ContentRegion(text: text, locator: locator, baseOffset: offset, offsetMap: nil,
                             hasEscapes: false, offsetsReliable: text.utf8.count == bytes.count)
    }

    /// A cell's raw bytes and whether the column held it as a blob (so a rewrite rebinds the same type).
    func cellBytes(_ v: SQLiteValue?) -> (bytes: [UInt8], isBlob: Bool)? { SQLiteCellRedactor.cellBytes(v) }

    // MARK: Activity

    public func activeState(artifact: Artifact) async -> ArtifactActivity {
        let age = Date().timeIntervalSince(artifact.identity.modified)
        guard age < activityWindow else { return .inactive }
        // Tightened: active only if the owning editor is actually running (recent write alone isn't enough), or a
        // SQLite DB has a live `-wal` (something has it open). A recent file whose editor is closed is safe to
        // redact; and even a misjudgement here is caught by the transactional cell rewrite / preimage re-check.
        let editor = editorName(for: artifact.url)
        if !editor.isEmpty, RunningProcesses.isRunning(editor) {
            return .active(reason: "\(editor) is running and the store changed \(Int(age))s ago")
        }
        if artifact.kind == .sqlite, SQLiteDatabase.hasLiveWAL(forDBAt: artifact.url.path) {
            return .active(reason: "database has a live WAL and changed \(Int(age))s ago")
        }
        return .inactive
    }

    /// The editor's Application Support folder name (e.g. "Code", "Cursor", "Windsurf", "VSCodium"), which is also
    /// its process name — used to check whether that editor is currently running.
    private func editorName(for url: URL) -> String {
        let comps = url.pathComponents
        if let i = comps.firstIndex(of: "Application Support"), i + 1 < comps.count { return comps[i + 1] }
        return ""
    }

    // MARK: Mutation

    public func redactionConstraint(for occurrence: SecretOccurrence, in store: StoreDescriptor) -> RedactionDeferral? {
        if store.tier == .excluded { return .storeReadOnly }
        // A SQLite cell is rewritten whole, same-length, inside a transaction — never resized. An escaped value
        // that would need a variable-length rewrite is deferred rather than risking the cell. (A same-length
        // raw-byte rewrite of a binary cell is allowed through here; the engine gates it on the caller's opt-in.)
        if case .sqliteCell = occurrence.recordLocator, occurrence.feasibility.editKind == .resizeRecord {
            return .requiresSemanticRewrite
        }
        return nil
    }

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
        let db = try openForReading(occurrence.artifactURL.path)
        guard let v = try db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"],
              let (bytes, _) = cellBytes(v) else { return nil }
        let range = occurrence.serializedByteRange
        guard range.upperBound <= bytes.count else { return nil }
        let start = max(0, range.lowerBound - before)
        return (Array(bytes[start..<min(bytes.count, range.upperBound + after)]), start)
    }

    public func rawContainerBytes(for occurrence: SecretOccurrence) throws -> [UInt8]? {
        guard case let .sqliteCell(table, rowid, column) = occurrence.recordLocator else {
            return Array(try Data(contentsOf: occurrence.artifactURL))
        }
        let db = try openForReading(occurrence.artifactURL.path)
        guard let v = try db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"],
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
        // A text cell that currently parses as JSON must still parse after the rewrite; a blob is binary (the
        // shared redactor skips the JSON check for it and preserves the BLOB type).
        let policy = SQLiteCellRedactor.Policy(busyWriter: "the editor") { _, originalBytes, wasBlob in
            !wasBlob && (try? self.walker.strings(in: originalBytes)) != nil
        }
        outcomes.merge(SQLiteCellRedactor().apply(cellTargets, verifyPreimage: verifyPreimage, policy: policy)) { a, _ in a }
        return RedactionResult(outcomes: outcomes)
    }
}
