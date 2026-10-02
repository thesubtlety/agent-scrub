import Foundation
import Testing
import HistoryGuardCore
import HistoryGuardDB
import SecretDetection
import ClaudeCodeAdapter
@testable import StoreMonitoring

@Suite struct MonitorServiceTests {
    // Copies Fixtures/Claude/version-A into a temp dir so a test can mutate it.
    func fixtureCopy() throws -> URL {
        let here = URL(fileURLWithPath: #filePath)   // .../Tests/StoreMonitoringTests/MonitorServiceTests.swift
        let repo = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let src = repo.appendingPathComponent("Fixtures/Claude/version-A")
        let dst = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.copyItem(at: src, to: dst)
        return dst
    }

    // Synchronous enumeration helper: NSEnumerator's Sequence is unavailable in async contexts.
    func firstJSONL(under dir: URL) -> URL? {
        let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)
        while let u = e?.nextObject() as? URL { if u.pathExtension == "jsonl" { return u } }
        return nil
    }

    // The StateStore is created here and handed to the actor, which owns it exclusively (it is not
    // Sendable), so makeService does not return it. Cursor/event persistence is covered by StateStoreTests.
    func makeService(root: URL, stateURL: URL? = nil, key: InstallationKey = .random()) throws -> (MonitorService, ManualChangeSource) {
        let adapter: any AgentAdapter = ClaudeCodeAdapter(additionalRoots: [root], includeDefaultRoots: false)
        let inst = AgentInstallation(adapterID: adapter.id, rootURL: root, version: nil)
        let state = try StateStore(url: stateURL ?? FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".sqlite"))
        let source = ManualChangeSource()
        let service = MonitorService(
            pairs: [(adapter: adapter, installation: inst)],
            scanner: SecretScanner(catalog: try RuleCatalog.bundled()),
            fingerprinter: Fingerprinter(key: key),
            state: state, changeSource: source)
        return (service, source)
    }

    @Test func initialSweepFindsSeededSecrets() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let state = await service.currentState()
        #expect(!state.secrets.isEmpty)          // version-A seeds fake secrets in every known store
        #expect(!state.stores.isEmpty)           // stores are reported (not "0 configured")
        #expect(state.scanning == false)          // sweep finished
        #expect(state.status == .yellow)          // findings present
    }

    @Test func appendedTokenAppearsViaDelta() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let before = await service.currentState().occurrences.count

        let transcript = try #require(firstJSONL(under: root.appendingPathComponent("projects")))
        let fh = try FileHandle(forWritingTo: transcript); try fh.seekToEnd()
        try fh.write(contentsOf: Data("{\"type\":\"user\",\"message\":{\"content\":\"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\"}}\n".utf8))
        try fh.close()

        await service.reconcileAll()
        let after = await service.currentState().occurrences.count
        #expect(after > before)   // the appended token was found via a delta scan, not a full-tree rescan
    }

    // A removed file drops its occurrences and does not crash reconciliation.
    @Test func removedFileDropsOccurrences() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let historyURL = root.appendingPathComponent("history.jsonl")
        if FileManager.default.fileExists(atPath: historyURL.path) {
            try FileManager.default.removeItem(at: historyURL)
            await service.reconcileAll()
        }
        let state = await service.currentState()
        #expect(!state.occurrences.contains { $0.artifactURL == historyURL })
    }

    // The change-source subscription delivers a dropped batch to reconcileAll without crashing.
    @Test func droppedEventsBatchIsConsumed() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let (service, source) = try makeService(root: root)
        await service.start()
        source.push(FileChangeBatch(changedPaths: [], dropped: true))
        try await Task.sleep(nanoseconds: 300_000_000)
        let state = await service.currentState()
        await service.stop()
        #expect(!state.secrets.isEmpty)
    }

    // C1: a restart (new service over the same persisted cursors) must not lose secrets in unchanged files.
    @Test func restartDoesNotLoseSecretsInUnchangedFiles() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let stateURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".sqlite")
        defer { for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(at: URL(fileURLWithPath: stateURL.path + s)) } }

        let (s1, _) = try makeService(root: root, stateURL: stateURL)
        await s1.reconcileAll()
        let first = await s1.currentState().secrets.count
        #expect(first > 0)

        // New process: a fresh service over the SAME state DB (cursors persisted), files unchanged.
        let (s2, _) = try makeService(root: root, stateURL: stateURL)
        await s2.reconcileAll()
        let second = await s2.currentState().secrets.count
        #expect(second == first)
    }

    // Redaction: overwrite the secret in place, keep the record valid JSON, and verify it is gone.
    @Test func redactRemovesSecretAndVerifies() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-redact-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-000000000001.jsonl")
        try Data(("{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n").utf8).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secret = try #require(await service.currentState().secrets.first)

        let outcome = await service.redact(fingerprint: secret.fingerprint)
        #expect(outcome.applied >= 1)
        #expect(outcome.remaining == 0)
        #expect(outcome.isVerifiedClean)

        let content = try String(contentsOf: file, encoding: .utf8)
        #expect(!content.contains(token))                                    // the secret is gone
        let firstLine = try #require(content.split(separator: "\n").first)
        #expect((try? JSONSerialization.jsonObject(with: Data(firstLine.utf8))) != nil)   // record still parses
    }

    // A secret whose match boundary is a quote (curl -H "Authorization: Bearer …") lives in a JSONL message
    // where the quotes are escaped (\"). Byte-preserving redaction must still remove it: verification has to
    // use the same decoded extraction as detection, not a raw re-scan that trips over the escaped boundary and
    // reports "the file changed since the scan".
    @Test func redactsSecretWithEscapedQuoteBoundary() async throws {
        let token = "sk_live_FAKEtoken1234567890abcdEFGHijkl"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-redact-esc-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-000000000002.jsonl")
        let content = "{\"type\":\"assistant\",\"message\":{\"content\":\"run: curl -H \\\"Authorization: Bearer \(token)\\\" https://api.example.com\"}}\n"
        try Data(content.utf8).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secrets = await service.currentState().secrets
        #expect(!secrets.isEmpty)

        for s in secrets { _ = await service.redact(fingerprint: s.fingerprint) }

        let after = try String(contentsOf: file, encoding: .utf8)
        #expect(!after.contains(token))                                       // the secret is gone
        let firstLine = try #require(after.split(separator: "\n").first)
        #expect((try? JSONSerialization.jsonObject(with: Data(firstLine.utf8))) != nil)   // record still parses
    }

    // A secret discovered by an incremental (delta) rescan carries a delta-relative line index in its locator,
    // while a full re-extraction numbers lines from the file start. Redaction must still remove it — the appended,
    // actively-written transcript is the common case, and keying verification on the line index breaks it.
    @Test func redactsSecretFoundByDeltaRescan() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-redact-delta-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-000000000003.jsonl")
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"hello world\"}}\n".utf8).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()   // scans line 0; cursor advances past it

        // Append the secret on a new line, then reconcile again → a delta scan from the cursor numbers this
        // line as 0, not its true file line number.
        let line2 = "{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n"
        let fh = try FileHandle(forWritingTo: file)
        try fh.seekToEnd(); try fh.write(contentsOf: Data(line2.utf8)); try fh.close()
        await service.reconcileAll()

        let secret = try #require(await service.currentState().secrets.first)
        let outcome = await service.redact(fingerprint: secret.fingerprint)
        #expect(outcome.applied >= 1)
        #expect(outcome.remaining == 0)
        #expect(!(try String(contentsOf: file, encoding: .utf8)).contains(token))
    }

    // Fingerprints are HMACs under the installation key. If the key changes, persisted findings (keyed by the
    // old key) must be dropped on relaunch, or they shadow the fresh scan and can never be redacted — the real
    // cause of "range matched but fingerprint differs".
    @Test func changedInstallationKeyInvalidatesPersistedFindings() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let stateURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".sqlite")

        let (s1, _) = try makeService(root: root, stateURL: stateURL, key: .random())
        await s1.reconcileAll()
        let firstFingerprints = Set(await s1.currentState().secrets.map(\.fingerprint))
        #expect(!firstFingerprints.isEmpty)

        // Relaunch against the same store with a different key. The seeded (old-key) findings must not survive.
        let (s2, _) = try makeService(root: root, stateURL: stateURL, key: .random())
        let seeded = Set(await s2.currentState().secrets.map(\.fingerprint))
        #expect(seeded.isDisjoint(with: firstFingerprints))   // nothing stale carried over before a rescan
        await s2.reconcileAll()
        #expect(!(await s2.currentState().secrets.isEmpty))    // a fresh scan repopulates under the new key
    }

    // Lifetime redaction totals persist across relaunches (they live in the store's meta, not the findings).
    @Test func lifetimeRedactionCountersPersist() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-lifetime-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n".utf8)
            .write(to: dir.appendingPathComponent("00000000-0000-4000-8000-000000000009.jsonl"))
        defer { try? fm.removeItem(at: root) }
        let stateURL = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".sqlite")
        let key = InstallationKey.random()

        let (s1, _) = try makeService(root: root, stateURL: stateURL, key: key)
        await s1.reconcileAll()
        let secret = try #require(await s1.currentState().secrets.first)
        _ = await s1.redact(fingerprint: secret.fingerprint)
        let after = await s1.currentState()
        #expect(after.lifetimeCopiesRedacted >= 1)
        #expect(after.lifetimeSecretsRedacted >= 1)

        // Relaunch against the same store: the totals are still there.
        let (s2, _) = try makeService(root: root, stateURL: stateURL, key: key)
        await s2.reconcileAll()
        #expect(await s2.currentState().lifetimeCopiesRedacted >= 1)
    }

    // Semantic rewrite end-to-end: a key whose value holds escaped newlines (a PEM inside a JSON message) is
    // removed via a resizing rewrite, the record stays valid JSON, and the verify scan confirms it's gone.
    @Test func redactsEscapedValueEndToEnd() async throws {
        let body = "MIIBOwIBAAJBAK" + String(repeating: "FAKEbase64Material0123456789", count: 4)
        let pem = "-----BEGIN RSA PRIVATE KEY-----\\n\(body)\\n-----END RSA PRIVATE KEY-----"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-sem-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-00000000000a.jsonl")
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"\(pem)\"}}\n".utf8).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secret = try #require(await service.currentState().secrets.first { $0.kind == .privateKey })
        let outcome = await service.redact(fingerprint: secret.fingerprint)
        #expect(outcome.applied >= 1)
        #expect(outcome.remaining == 0)

        let after = try String(contentsOf: file, encoding: .utf8)
        #expect(!after.contains(body))                                       // the key body is gone
        let firstLine = try #require(after.split(separator: "\n").first)
        #expect((try? JSONSerialization.jsonObject(with: Data(firstLine.utf8))) != nil)   // record still parses
    }

    // Always-redact enforcement: once a fingerprint is marked, a reconcile removes every copy automatically.
    @Test func autoRedactEnforcedOnReconcile() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-auto-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-00000000000b.jsonl")
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n".utf8).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secret = try #require(await service.currentState().secrets.first)

        // Marking it enforces immediately; a later scan keeps enforcing.
        await service.setAutoRedact([secret.fingerprint])
        #expect(await service.currentState().occurrences.allSatisfy { $0.fingerprint != secret.fingerprint })
        #expect(!(try String(contentsOf: file, encoding: .utf8)).contains(token))
    }

    // Excluding a folder drops it from scanning and prunes any findings already under it.
    @Test func exclusionsSkipFolder() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-excl-\(UUID().uuidString)")
        let dirA = root.appendingPathComponent("projects/-Users-dev-a")
        let dirB = root.appendingPathComponent("projects/-Users-dev-b")
        try fm.createDirectory(at: dirA, withIntermediateDirectories: true)
        try fm.createDirectory(at: dirB, withIntermediateDirectories: true)
        let line = "{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n"
        try Data(line.utf8).write(to: dirA.appendingPathComponent("00000000-0000-4000-8000-00000000000c.jsonl"))
        try Data(line.utf8).write(to: dirB.appendingPathComponent("00000000-0000-4000-8000-00000000000d.jsonl"))
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        #expect(await service.currentState().occurrences.count == 2)

        await service.setExclusions([dirA.path])
        await service.reconcileAll()
        let occ = await service.currentState().occurrences
        #expect(occ.count == 1)
        #expect(occ.allSatisfy { !$0.artifactURL.path.hasPrefix(dirA.path) })
    }

    // Expired JWTs are dropped at scan time; a live one is still found.
    @Test func expiredJWTsAreNotSurfaced() async throws {
        func b64url(_ s: String) -> String {
            Data(s.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        func jwt(_ payload: String) -> String {
            "\(b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")).\(b64url(payload)).abcdefghij1234567890"
        }
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-jwt-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let expired = jwt("{\"exp\":1000000000,\"sub\":\"u\"}")   // 2001
        let live = jwt("{\"sub\":\"u\",\"role\":\"admin\"}")       // no exp
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"\(expired)\"}}\n".utf8)
            .write(to: dir.appendingPathComponent("00000000-0000-4000-8000-00000000000e.jsonl"))
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"\(live)\"}}\n".utf8)
            .write(to: dir.appendingPathComponent("00000000-0000-4000-8000-00000000000f.jsonl"))
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let jwts = await service.currentState().secrets.filter { $0.kind == .jwt }
        #expect(jwts.count == 1)   // the live one; the expired one is dropped
    }

    // C1: a plain-text file with invalid UTF-8 before a secret has an untrustworthy byte range — redaction must
    // refuse to rewrite it rather than splice at the wrong offset and corrupt the file.
    @Test func plainTextWithInvalidUTF8IsNeverRewritten() async throws {
        let token = "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"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-badutf8-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("shell-snapshots")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("snapshot.sh")
        // A lone 0x80 (invalid UTF-8, not NUL so not treated as binary) before the token shifts decoded offsets.
        var raw = Array("export KEY=".utf8); raw.append(0x80); raw += Array(" \(token)\n".utf8)
        try Data(raw).write(to: file)
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secret = try #require(await service.currentState().secrets.first { $0.kind == .githubToken })
        let before = try Data(contentsOf: file)

        let outcome = await service.redact(fingerprint: secret.fingerprint)
        #expect(outcome.applied == 0)                       // refused, not spliced
        #expect(try Data(contentsOf: file) == before)       // file byte-for-byte unchanged (no corruption)
    }

    // H1: a resize (variable-length) rewrite of a LIVE file would drop the agent's concurrent appends, so even
    // "include active sessions" must defer a resize-eligible secret in an active file.
    @Test func activeResizeDefersEvenWithAllowActive() async throws {
        let body = "MIIBOwIBAAJBAK" + String(repeating: "FAKEbase64Material0123456789", count: 4)
        let pem = "-----BEGIN RSA PRIVATE KEY-----\\n\(body)\\n-----END RSA PRIVATE KEY-----"
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-activeresize-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        try fm.createDirectory(at: root.appendingPathComponent("sessions"), withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-000000000010.jsonl")
        try Data("{\"type\":\"user\",\"message\":{\"content\":\"\(pem)\"}}\n".utf8).write(to: file)
        // Mark the installation active: a live session for this process + a just-written transcript.
        try Data("{}".utf8).write(to: root.appendingPathComponent("sessions/\(ProcessInfo.processInfo.processIdentifier).json"))
        defer { try? fm.removeItem(at: root) }

        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let secret = try #require(await service.currentState().secrets.first { $0.kind == .privateKey })
        let before = try Data(contentsOf: file)

        let outcome = await service.redact(fingerprint: secret.fingerprint, allowActive: true)
        #expect(outcome.applied == 0)                       // resize on a live file is refused
        #expect(try Data(contentsOf: file) == before)       // the agent's file is untouched
    }

    // I2: overlapping reconciles must not double-count occurrences.
    @Test func concurrentReconcilesDoNotDuplicate() async throws {
        let root = try fixtureCopy(); defer { try? FileManager.default.removeItem(at: root) }
        let (service, _) = try makeService(root: root)
        await service.reconcileAll()
        let baseline = await service.currentState().occurrences.count
        async let r1: Void = service.reconcileAll()
        async let r2: Void = service.reconcileAll()
        _ = await (r1, r2)
        let after = await service.currentState().occurrences.count
        #expect(after == baseline)
    }
}
