import CodexAdapter
import Foundation
import HistoryGuardCore
import SecretDetection
import SQLiteSupport
import Testing

struct CodexSandbox {
    let root: URL
    let adapter = CodexAdapter()
    let scanner = SecretScanner(catalog: try! RuleCatalog.bundled())
    let fingerprinter = Fingerprinter(key: InstallationKey(data: Data(repeating: 6, count: 32)))

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("hg-codex-redact-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: install("version-A").rootURL, to: root)
        let old = Date(timeIntervalSinceNow: -86400)
        for case let u as URL in FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)! {
            try FileManager.default.setAttributes([.modificationDate: old], ofItemAtPath: u.path)
        }
    }
    func destroy() { try? FileManager.default.removeItem(at: root) }
    var installation: AgentInstallation { AgentInstallation(adapterID: adapter.id, rootURL: root, version: nil) }
    var scan: ScanEngine { ScanEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }
    var redaction: RedactionEngine { RedactionEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }
    var options: ScanOptions { ScanOptions(includeExtended: true) }

    /// Full dump of a database's cells for before/after comparison.
    func dump(_ name: String) throws -> [String: SQLiteValue] {
        let db = try SQLiteDatabase(path: root.appendingPathComponent(name).path)
        var out: [String: SQLiteValue] = [:]
        for t in try db.tables() {
            for row in try db.query("SELECT rowid AS __r, * FROM \(db.quoteIdentifier(t))") {
                for (k, v) in row where k != "__r" { out["\(t)[\(row["__r"]!.integer!)].\(k)"] = v }
            }
        }
        return out
    }
}

@Suite(.serialized) struct CodexRedactionTests {
    @Test func redactsFilesAndSQLiteCellsThenVerifiesClean() async throws {
        let sb = try CodexSandbox(); defer { sb.destroy() }
        let before = try await sb.scan.scan(installation: sb.installation, options: sb.options)
        let gh = try #require(before.secrets.first { $0.kind == .githubToken })
        #expect(before.occurrences(of: gh).count == 10)
        let stateBefore = try sb.dump("state_5.sqlite")
        let historyBefore = try sb.dump("thread_history_1.sqlite")

        let (plan, result) = try await sb.redaction.redact(report: before, fingerprints: [gh.fingerprint], options: RedactionOptions(scanOptions: sb.options))
        #expect(plan.deferred.isEmpty, "\(plan.deferred)")
        #expect(plan.targets.count == 10)
        #expect(result.appliedCount == 10, "\(result.failed)")

        // Only the six cells holding the token changed; every other cell is byte-identical.
        let stateAfter = try sb.dump("state_5.sqlite")
        let historyAfter = try sb.dump("thread_history_1.sqlite")
        var changed = 0
        for (k, v) in stateBefore where stateAfter[k] != v { changed += 1; #expect(stateAfter[k]?.text?.contains("[REDACTED:GITHUB:") == true, "\(k)") }
        for (k, v) in historyBefore where historyAfter[k] != v { changed += 1; #expect(historyAfter[k]?.text?.contains("[REDACTED:GITHUB:") == true, "\(k)") }
        #expect(changed == 5)   // title, first_user_message, preview, thread_items x2 (logs db counted separately)
        // JSON cells still parse.
        let db = try SQLiteDatabase(path: sb.root.appendingPathComponent("thread_history_1.sqlite").path)
        for row in try db.query("SELECT item_json FROM thread_items") {
            #expect(throws: Never.self) { _ = try JSONStringWalker().strings(in: Array(row["item_json"]!.text!.utf8)) }
        }
        #expect(try db.integrityOK())

        // Independent verification: zero copies remain. The fixture's deliberate unknown-store gap blocks the clean claim.
        let v = try #require(try await sb.redaction.verify(installation: sb.installation, fingerprints: [gh.fingerprint], scanOptions: sb.options)[gh.fingerprint])
        #expect(v.occurrencesRemaining.isEmpty)
        try FileManager.default.removeItem(at: sb.root.appendingPathComponent("plugins-cache"))
        try FileManager.default.removeItem(at: sb.root.appendingPathComponent("sessions/2026/09/29/notes.txt"))
        let after = try await sb.scan.scan(installation: sb.installation, options: sb.options)
        // goals_1.sqlite has no schema handler: its unsupported-schema gap keeps the overall claim blocked, by design.
        #expect(after.gaps.allSatisfy { if case .unsupportedSchema = $0.reason { return true } else { return false } })
        #expect(!after.occurrences.contains { $0.fingerprint == gh.fingerprint })
    }

    @Test func unknownSchemaDatabaseIsNeverWritten() async throws {
        let sb = try CodexSandbox(); defer { sb.destroy() }
        let report = try await sb.scan.scan(installation: sb.installation, options: sb.options)
        let dbURL = try #require(report.secrets.first { $0.kind == .databaseURL && $0.maskedDisplay.contains("db.payments.internal") })
        let plan = await sb.redaction.plan(report: report, fingerprints: [dbURL.fingerprint], options: RedactionOptions(scanOptions: sb.options))
        let goals = report.occurrences(of: dbURL).filter { $0.storeID.rawValue == "other-db" }
        #expect(goals.count == 1)
        #expect(plan.deferred[goals[0].id] == .storeReadOnly)
        #expect(plan.targets.contains { $0.storeID.rawValue == "prompt-history" })
    }

    @Test func busyDatabaseIsReportedNotForced() async throws {
        let sb = try CodexSandbox(); defer { sb.destroy() }
        let report = try await sb.scan.scan(installation: sb.installation, options: sb.options)
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let plan = await sb.redaction.plan(report: report, fingerprints: [gh.fingerprint], options: RedactionOptions(scanOptions: sb.options))
        let cells = plan.targets.filter { $0.artifactURL.lastPathComponent == "state_5.sqlite" }
        #expect(cells.count == 3)

        // Another writer holds the database.
        let writer = try SQLiteDatabase(path: sb.root.appendingPathComponent("state_5.sqlite").path, readOnly: false)
        try writer.execute("BEGIN IMMEDIATE")
        let blocked = try await sb.adapter.apply(plan: RedactionPlan(targets: cells, deferred: [:]), verifyPreimage: sb.redaction.preimageVerifier())
        #expect(blocked.appliedCount == 0)
        #expect(blocked.outcomes.values.allSatisfy { if case .ioError(let m) = $0 { return m.contains("busy") } else { return false } }, "\(blocked.outcomes)")
        try writer.execute("ROLLBACK")

        let ok = try await sb.adapter.apply(plan: RedactionPlan(targets: cells, deferred: [:]), verifyPreimage: sb.redaction.preimageVerifier())
        #expect(ok.appliedCount == 3, "\(ok.failed)")
        let again = try await sb.adapter.apply(plan: RedactionPlan(targets: cells, deferred: [:]), verifyPreimage: sb.redaction.preimageVerifier())
        #expect(again.outcomes.values.allSatisfy { $0 == .alreadyApplied })
    }
}
