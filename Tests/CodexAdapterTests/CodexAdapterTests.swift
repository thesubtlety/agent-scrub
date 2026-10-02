import CodexAdapter
import Foundation
import HistoryGuardCore
import SecretDetection
import SQLiteSupport
import Testing

func fixturesRoot() -> URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures")
}
func install(_ name: String) -> AgentInstallation {
    AgentInstallation(adapterID: AdapterID("codex"), rootURL: fixturesRoot().appendingPathComponent("Codex/\(name)"), version: nil)
}
func engine() throws -> ScanEngine {
    ScanEngine(adapter: CodexAdapter(), scanner: SecretScanner(catalog: try RuleCatalog.bundled()),
               fingerprinter: Fingerprinter(key: InstallationKey(data: Data(repeating: 5, count: 32))))
}
func values() throws -> [String: String] {
    try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
}

@Suite struct CodexStoreTests {
    @Test func storesAreClaimedAndSchemasClassified() async throws {
        let (stores, gaps) = try await CodexAdapter().enumerateStores(installation: install("version-A"))
        let byID = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        for id in ["prompt-history", "rollouts", "archived-rollouts", "session-index", "state-db", "thread-history-db", "logs-db", "other-db",
                   "credentials", "settings", "writer-locks", "extensions"] {
            #expect(byID[id]?.present == true, "\(id)")
        }
        #expect(byID["state-db"]?.schema == .known(version: "codex-rs 2026-09"))
        #expect(byID["thread-history-db"]?.capabilities.contains(.redactWhenInactive) == true)
        if case .unknown = byID["other-db"]?.schema {} else { Issue.record("goals db should be an unknown schema") }
        #expect(byID["other-db"]?.capabilities.contains(.redactWhenInactive) == false)
        #expect(byID["credentials"]?.tier == .excluded)
        #expect(gaps.count == 1)
        #expect(gaps.first?.path.hasSuffix("plugins-cache") == true)
    }

    @Test func rolloutsAreFoundUnderDateShardsAndThreadIDsParsed() async throws {
        let adapter = CodexAdapter()
        let (stores, _) = try await adapter.enumerateStores(installation: install("version-A"))
        let rollouts = try await adapter.enumerateArtifacts(store: stores.first { $0.id.rawValue == "rollouts" }!, cursor: nil)
        #expect(rollouts.artifacts.count == 1)
        #expect(rollouts.artifacts.first?.sessionID == "0199a3f0-0000-7000-8000-00000000c0de")
        #expect(rollouts.gaps.contains { $0.path.hasSuffix("notes.txt") && $0.reason == .unknownStore })
        let archived = try await adapter.enumerateArtifacts(store: stores.first { $0.id.rawValue == "archived-rollouts" }!, cursor: nil)
        #expect(archived.artifacts.first?.sessionID == "0199a3f0-0000-7000-8000-00000000a5c1")
        #expect(CodexAdapter.threadID(fromRolloutName: "rollout-2026-09-29T07-14-22-0199a3f0-0000-7000-8000-00000000c0de_9f.jsonl") == "0199a3f0-0000-7000-8000-00000000c0de")
    }
}

@Suite struct CodexScanTests {
    @Test func githubTokenIsFoundInEveryDuplicateStore() async throws {
        let report = try await engine().scan(installation: install("version-A"), options: ScanOptions(includeExtended: true))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let byStore = Dictionary(grouping: report.occurrences(of: gh), by: { $0.storeID.rawValue }).mapValues(\.count)
        // history.jsonl, rollout (user + assistant), session index thread name, state db (title, first_user_message, preview),
        // thread history (user item + agent item), logs db
        #expect(byStore == ["prompt-history": 1, "rollouts": 2, "session-index": 1, "state-db": 3, "thread-history-db": 2, "logs-db": 1], "\(byStore)")
        #expect(!report.occurrences.contains { $0.artifactURL.path.contains("plugins-cache") })
    }

    @Test func excludedAuthFileIsNeverScanned() async throws {
        let report = try await engine().scan(installation: install("version-A"), options: ScanOptions(includeExtended: true))
        #expect(!report.secrets.contains { $0.kind == .openAIKey })
        // The JWT lives in auth.json (excluded) and in a realtime item (scanned): exactly one identity, one copy.
        let jwt = report.secrets.filter { $0.kind == .jwt }
        #expect(jwt.count == 1)
        #expect(report.occurrences(of: jwt[0]).count == 1)
        #expect(report.occurrences(of: jwt[0]).first?.storeID.rawValue == "thread-history-db")
    }

    @Test func sqliteCellRangesAreExact() async throws {
        let report = try await engine().scan(installation: install("version-A"), options: ScanOptions(includeExtended: true))
        let gh = try #require(values()["github"])
        for o in report.occurrences where o.storeID.rawValue.hasSuffix("-db") {
            guard case let .sqliteCell(table, rowid, column) = o.recordLocator else { Issue.record("expected sqlite locator"); continue }
            let db = try SQLiteDatabase(path: o.artifactURL.path)
            let cell = try #require(db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"]?.text)
            let bytes = Array(cell.utf8)
            let slice = String(decoding: bytes[o.serializedByteRange], as: UTF8.self)
            let secret = report.secrets.first { $0.id == o.secretID }!
            if secret.kind == .githubToken { #expect(slice == gh, "\(table).\(column)") }
            #expect(o.feasibility == .byteLengthPreserving)
        }
    }

    @Test func unknownSchemaIsScannedButFlagged() async throws {
        let report = try await engine().scan(installation: install("version-A"), options: ScanOptions(includeExtended: true))
        let dbURL = try #require(report.secrets.first { $0.kind == .databaseURL && $0.maskedDisplay.contains("db.payments.internal") })
        #expect(report.occurrences(of: dbURL).contains { $0.storeID.rawValue == "other-db" })
        #expect(report.gaps.contains { g in if case .unsupportedSchema = g.reason { return g.path.hasSuffix("goals_1.sqlite") } else { return false } })
        // The https git remote with embedded credentials in threads.git_origin_url is a separate identity.
        #expect(report.secrets.contains { $0.kind == .databaseURL && $0.maskedDisplay.contains("github.com") })
    }

    @Test func writerLockMeansActive() async throws {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("hg-codex-\(UUID().uuidString)")
        try fm.copyItem(at: install("version-A").rootURL, to: tmp)
        defer { try? fm.removeItem(at: tmp) }
        let old = Date(timeIntervalSinceNow: -86400)
        let en = fm.enumerator(at: tmp, includingPropertiesForKeys: nil)!
        while let u = en.nextObject() as? URL { try fm.setAttributes([.modificationDate: old], ofItemAtPath: u.path) }
        let adapter = CodexAdapter()
        let rollout = tmp.appendingPathComponent("sessions/2026/09/29/rollout-2026-09-29T07-14-22-0199a3f0-0000-7000-8000-00000000c0de.jsonl")
        let art = Artifact(url: rollout, storeID: StoreID("rollouts"), kind: .jsonl, identity: try FileIdentity.read(at: rollout), sessionID: "0199a3f0-0000-7000-8000-00000000c0de")
        #expect(await adapter.activeState(artifact: art) == .inactive)

        // Hold the thread's writer lock the way Codex does.
        let lockPath = tmp.appendingPathComponent("thread-writer-locks/0199a3f0-0000-7000-8000-00000000c0de.lock").path
        let fd = open(lockPath, O_RDWR)
        #expect(fd >= 0)
        #expect(flock(fd, LOCK_EX | LOCK_NB) == 0)
        guard case .active = await adapter.activeState(artifact: art) else { Issue.record("expected active while lock held"); flock(fd, LOCK_UN); close(fd); return }
        flock(fd, LOCK_UN); close(fd)
        #expect(await adapter.activeState(artifact: art) == .inactive)
    }
}
