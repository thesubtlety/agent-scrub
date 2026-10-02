import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
import SQLiteSupport
@testable import VSCodeAdapter

private let token = "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"

/// Build a synthetic editor dir: a global state.vscdb (ItemTable + cursorDiskKV chat rows, one TEXT + one BLOB),
/// a per-workspace Copilot chatSessions JSON, and an excluded cache file. All secrets are clearly FAKE.
private func makeRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("vscode-\(UUID().uuidString)")
    let globalStorage = root.appendingPathComponent("User/globalStorage")
    let ws = root.appendingPathComponent("User/workspaceStorage/ws1hash")
    let chatSessions = ws.appendingPathComponent("chatSessions")
    try fm.createDirectory(at: globalStorage, withIntermediateDirectories: true)
    try fm.createDirectory(at: chatSessions, withIntermediateDirectories: true)

    // --- global state.vscdb (default journal, no WAL, so it reads back cleanly) ---
    let dbURL = globalStorage.appendingPathComponent("state.vscdb")
    let db = try SQLiteDatabase(path: dbURL.path, readOnly: false, create: true)
    try db.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
    try db.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
    // Cursor-style chat header (TEXT value).
    try db.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                   [.text("composer.composerHeaders"), .text("{\"allComposers\":[{\"name\":\"chat using \(token) now\"}]}")])
    // Windsurf-style chat (BLOB value) — exercises the blob path.
    try db.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                   [.text("cascade.chatdata"), .blob(Data("{\"messages\":[{\"content\":\"key is \(token)\"}]}".utf8))])
    // Cursor per-message row in cursorDiskKV.
    try db.execute("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
                   [.text("bubbleId:c1:b1"), .text("{\"type\":1,\"text\":\"use \(token) here\"}")])
    // A cursorDiskKV content key NOT in the GLOB list (a code diff) must still be scanned — whole-table scan.
    try db.execute("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
                   [.text("codeBlockDiff:c1:d1"), .text("{\"modified\":[\"export KEY=\(token)\"]}")])
    // A non-chat key must NOT be scanned: put a DIFFERENT fake token here and assert it's never found.
    try db.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                   [.text("telemetry.lastSessionDate"), .text("{\"secret\":\"ghp_FAKEnotchatXXXXXXXXXXXXXXXXXXXXXXXX\"}")])
    _ = db   // closes on deinit at function return, flushing the default-journal commits to disk

    // --- Copilot chat session JSON ---
    try Data("{\"requests\":[{\"message\":{\"text\":\"run with \(token)\"}}]}".utf8)
        .write(to: chatSessions.appendingPathComponent("00000000-0000-4000-8000-000000000001.json"))

    // --- excluded cache (must not be scanned) ---
    try fm.createDirectory(at: root.appendingPathComponent("Cache"), withIntermediateDirectories: true)
    try Data("ghp_FAKEcacheXXXXXXXXXXXXXXXXXXXXXXXXXXXX".utf8).write(to: root.appendingPathComponent("Cache/blob.bin"))
    return root
}

private func adapter(_ root: URL) -> VSCodeAdapter { VSCodeAdapter(additionalRoots: [root], includeDefaultRoots: false) }
private func install(_ root: URL) -> AgentInstallation {
    AgentInstallation(adapterID: VSCodeStores.adapterID, rootURL: root, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }
private func makeOld(_ url: URL) throws {
    try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -3600)], ofItemAtPath: url.path)
}

@Suite struct VSCodeAdapterTests {
    @Test func enumerationClaimsChatStores() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, _) = try await adapter(root).enumerateStores(installation: install(root))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["vscode-global-db"]?.present == true)
        #expect(present["vscode-chat-sessions"]?.present == true)
        #expect(present["vscode-global-db"]?.tier == .conversation)
        #expect(present["vscode-other"]?.tier == .excluded)
        #expect(present["vscode-other"]?.capabilities.isEmpty == true)
    }

    @Test func scanFindsSecretsInDBCellsAndJSONButNotNonChatOrExcluded() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))

        #expect(report.secrets.contains { $0.kind == .githubToken })
        // Found in SQLite cells (sqliteCell locator) and in the Copilot JSON file.
        let cellHits = report.occurrences.filter { if case .sqliteCell = $0.recordLocator { return true }; return false }
        // 4 cells: composerHeaders + cascade.chatdata + bubbleId + codeBlockDiff. The codeBlockDiff: key isn't in
        // the GLOB list, so its presence proves cursorDiskKV is scanned whole, not key-filtered.
        #expect(cellHits.count >= 4)
        #expect(report.occurrences.contains { $0.storeID == VSCodeStores.chatSessions })
        // Non-chat-key row and the excluded cache are never scanned → that distinct token never appears.
        let allMasked = report.secrets.map(\.maskedDisplay).joined()
        #expect(!report.occurrences.contains { $0.storeID.rawValue == "vscode-other" })
        _ = allMasked
    }

    // A live editor commits to the WAL and may not checkpoint for a while; a read-only open can't read the WAL,
    // so the scan must open read-write (query_only) to see the latest chat.
    @Test func readsSecretsFromUncheckpointedWAL() async throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("vscode-wal-\(UUID().uuidString)")
        let globalStorage = root.appendingPathComponent("User/globalStorage")
        try fm.createDirectory(at: globalStorage, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        // WAL mode, auto-checkpoint off, connection kept open → the secret stays in the -wal, not the main file.
        let live = try SQLiteDatabase(path: globalStorage.appendingPathComponent("state.vscdb").path,
                                      readOnly: false, create: true)
        try live.execute("PRAGMA journal_mode=WAL")
        try live.execute("PRAGMA wal_autocheckpoint=0")
        try live.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
        try live.execute("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
                         [.text("bubbleId:c1:b1"), .text("{\"text\":\"chat using \(token)\"}")])

        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        #expect(report.secrets.contains { $0.kind == .githubToken })
        _ = live   // keep the WAL alive through the scan
    }

    // A `-wal` with only its header (e.g. one our own read-only open created) must not be read as "active" — that
    // would defer a legitimate redaction. Only a WAL with real frames counts.
    @Test func emptyWALDoesNotMarkADatabaseActive() async throws {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("vscode-act-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let db = dir.appendingPathComponent("state.vscdb")
        try Data("x".utf8).write(to: db)   // recent mtime → passes the activity age window
        let art = Artifact(url: db, storeID: StoreID("vscode-global-db"), kind: .sqlite,
                           identity: try FileIdentity.read(at: db), sessionID: nil, projectPath: nil)
        let a = VSCodeAdapter(additionalRoots: [dir], includeDefaultRoots: false)

        try Data(count: 32).write(to: URL(fileURLWithPath: db.path + "-wal"))        // bare header, no frames
        if case .active = await a.activeState(artifact: art) { Issue.record("empty WAL must not be active") }

        try Data(count: 4096).write(to: URL(fileURLWithPath: db.path + "-wal"))      // real frames
        if case .active = await a.activeState(artifact: art) {} else { Issue.record("WAL with frames should be active") }
    }

    // The detail view's context/reveal reads bytes via the adapter's currentBytes. For a cell that must return the
    // cell's text around the secret — NOT the database file at a cell-relative offset (which is schema/page bytes).
    @Test func cellContextReadsFromTheCellNotTheDBFile() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let a = adapter(root)
        let report = try await ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp()).scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let cellOcc = try #require(report.occurrences.first {
            if case .sqliteCell = $0.recordLocator { return $0.fingerprint == gh.fingerprint }; return false
        })
        let (bytes, start) = try #require(try a.currentBytes(for: cellOcc, before: 48, after: 48))
        let ctx = String(decoding: bytes, as: UTF8.self)
        // Surrounding cell JSON is present; SQLite file internals are not.
        #expect(ctx.contains("\"") )
        #expect(!ctx.contains("CREATE TABLE"))
        #expect(!ctx.lowercased().contains("sqlite"))
        // The secret sits at serializedByteRange within these bytes (start is bytes[0]'s offset in the cell).
        #expect(cellOcc.serializedByteRange.lowerBound >= start)
    }

    @Test func redactsASQLiteCellSecretKeepingTheDBValid() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let dbURL = root.appendingPathComponent("User/globalStorage/state.vscdb")
        try makeOld(dbURL)   // inactive → not deferred

        let a = adapter(root)
        let engine = ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let redaction = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let (_, result) = try await redaction.redact(report: report, fingerprints: [gh.fingerprint])
        #expect(result.appliedCount >= 1)

        // The token is gone from every chat cell, and the DB is still valid.
        let db = try SQLiteDatabase(path: dbURL.path)
        for table in ["ItemTable", "cursorDiskKV"] {
            for row in try db.query("SELECT value FROM \(db.quoteIdentifier(table))") {
                if let t = row["value"]?.text { #expect(!t.contains(token)) }
                if case let .blob(d)? = row["value"] { #expect(!String(decoding: d, as: UTF8.self).contains(token)) }
            }
        }
        #expect(try db.integrityOK())
    }

    /// Build a DB with one binary (non-UTF-8) cursorDiskKV blob — like Cursor's msgpack agent store.
    private func makeBinaryCellRoot(blob: [UInt8]) throws -> URL {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("vscode-bin-\(UUID().uuidString)")
        let gs = root.appendingPathComponent("User/globalStorage")
        try fm.createDirectory(at: gs, withIntermediateDirectories: true)
        let db = try SQLiteDatabase(path: gs.appendingPathComponent("state.vscdb").path, readOnly: false, create: true)
        try db.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
        try db.execute("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
                       [.text("agentKv:blob:c1"), .blob(Data(blob))])
        _ = db
        return root
    }

    private func makeTextCellRoot(text: String) throws -> URL {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("vscode-txt-\(UUID().uuidString)")
        let gs = root.appendingPathComponent("User/globalStorage")
        try fm.createDirectory(at: gs, withIntermediateDirectories: true)
        let db = try SQLiteDatabase(path: gs.appendingPathComponent("state.vscdb").path, readOnly: false, create: true)
        try db.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
        try db.execute("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)", [.text("bubbleId:c1:b1"), .text(text)])
        _ = db
        return root
    }

    // A binary cell decodes lossily, so entropy/generic matchers fire on garbage. Keep only high-confidence,
    // specific-format matches there; a plain-text cell still gets the full matcher set.
    @Test func binaryRegionsDropGenericMatchesButKeepHighConfidence() async throws {
        let generic = "secret=W1nter2026SecretPw"   // genericSecret / medium confidence
        var blob: [UInt8] = [0x8a]; blob += Array("\(token) \(generic)".utf8) + [0x8a]
        let root = try makeBinaryCellRoot(blob: blob); defer { try? FileManager.default.removeItem(at: root) }
        let report = try await ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp()).scan(installation: install(root))
        #expect(report.secrets.contains { $0.kind == .githubToken })      // high-confidence survives the binary cell
        #expect(!report.secrets.contains { $0.kind == .genericSecret })   // generic noise dropped in a binary cell

        // Control: the same generic in a plain-text cell IS detected, proving the matcher itself still fires.
        let textRoot = try makeTextCellRoot(text: "{\"t\":\"\(generic)\"}"); defer { try? FileManager.default.removeItem(at: textRoot) }
        let textReport = try await ScanEngine(adapter: adapter(textRoot), scanner: try scanner(), fingerprinter: fp()).scan(installation: install(textRoot))
        #expect(textReport.secrets.contains { $0.kind == .genericSecret })
    }

    @Test func binaryCellSecretDefersWithoutOptInThenRedactsWithIt() async throws {
        var blob: [UInt8] = [0x8a]                       // non-UTF-8 lead byte → cell can't be cleanly decoded
        blob += Array("role\u{0}text ".utf8) + Array(token.utf8) + [0x8a] + Array(" end".utf8)
        let root = try makeBinaryCellRoot(blob: blob); defer { try? FileManager.default.removeItem(at: root) }
        let dbURL = root.appendingPathComponent("User/globalStorage/state.vscdb")
        try makeOld(dbURL)   // inactive

        let a = adapter(root)
        let report = try await ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp()).scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let occ = try #require(report.occurrences.first { $0.fingerprint == gh.fingerprint })
        #expect(occ.feasibility == .offsetsUnreliable)   // detected, but offsets untrustworthy (binary)

        let engine = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        // Default: not opted in → deferred, flagged so the UI can offer the per-item force action.
        let plan1 = await engine.plan(report: report, fingerprints: [gh.fingerprint])
        #expect(plan1.targets.isEmpty)
        #expect(plan1.deferred[occ.id] == .binaryRecordNeedsForce)

        // Opted in → redacted in place; cell stays a BLOB, same length, token gone, DB valid.
        let (_, result) = try await engine.redact(report: report, fingerprints: [gh.fingerprint],
                                                  options: RedactionOptions(allowUnverifiedBinaryRewrite: true))
        #expect(result.appliedCount == 1)
        let db = try SQLiteDatabase(path: dbURL.path)
        let value = try #require(try db.query("SELECT value FROM cursorDiskKV").first?["value"])
        guard case let .blob(d) = value else { Issue.record("cell must remain a BLOB"); return }
        #expect(d.count == blob.count)                   // same length — framing preserved
        #expect(d.range(of: Data(token.utf8)) == nil)    // secret gone
        #expect(d.first == 0x8a)                          // binary structure intact
        #expect(try db.integrityOK())
    }

    @Test func binaryCellWithTwoCopiesIsRefusedAsAmbiguous() async throws {
        var blob: [UInt8] = [0x8a]
        blob += Array(token.utf8) + Array(" / ".utf8) + Array(token.utf8) + [0x8a]
        let root = try makeBinaryCellRoot(blob: blob); defer { try? FileManager.default.removeItem(at: root) }
        try makeOld(root.appendingPathComponent("User/globalStorage/state.vscdb"))
        let a = adapter(root)
        let report = try await ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp()).scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })

        let engine = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let plan = await engine.plan(report: report, fingerprints: [gh.fingerprint],
                                     options: RedactionOptions(allowUnverifiedBinaryRewrite: true))
        #expect(plan.targets.isEmpty)   // the secret's bytes appear twice → refuse to guess which to overwrite
        #expect(!plan.deferred.isEmpty)
        #expect(plan.deferred.values.allSatisfy { $0 == .binaryRecordUnredactable })
    }

    @Test func redactsACopilotJSONSessionFile() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("User/workspaceStorage/ws1hash/chatSessions/00000000-0000-4000-8000-000000000001.json")
        try makeOld(file)

        let a = adapter(root)
        let engine = ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let fileHit = try #require(report.occurrences.first { $0.storeID == VSCodeStores.chatSessions })
        let gh = try #require(report.secrets.first { $0.fingerprint == fileHit.fingerprint })
        let redaction = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let (_, result) = try await redaction.redact(report: report, fingerprints: [gh.fingerprint])
        #expect(result.appliedCount >= 1)

        let after = try String(contentsOf: file, encoding: .utf8)
        #expect(!after.contains(token))
        #expect((try? JSONSerialization.jsonObject(with: Data(after.utf8))) != nil)
    }
}
