import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import GeminiAdapter

private let token = "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"

/// Build a synthetic ~/.gemini tree. All secret values are clearly FAKE.
private func makeRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("gemini-\(UUID().uuidString)")
    let chats = root.appendingPathComponent("tmp/hash1/chats")
    let ckpts = root.appendingPathComponent("tmp/hash1/checkpoints")
    try fm.createDirectory(at: chats, withIntermediateDirectories: true)
    try fm.createDirectory(at: ckpts, withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("weird-thing"), withIntermediateDirectories: true)

    try Data("{\"role\":\"user\",\"parts\":[{\"text\":\"use \(token) now\"}]}\n".utf8)
        .write(to: chats.appendingPathComponent("session-1.jsonl"))
    try Data("{\"entries\":[{\"text\":\"log line with \(token)\"}]}".utf8)
        .write(to: root.appendingPathComponent("tmp/hash1/logs.json"))
    try Data("{\"history\":[{\"content\":\"saved \(token)\"}]}".utf8)
        .write(to: ckpts.appendingPathComponent("checkpoint-foo.json"))
    try Data("# Context\n\nMy token is \(token)\n".utf8).write(to: root.appendingPathComponent("GEMINI.md"))
    // Excluded stores — carry a secret that must NOT be scanned.
    try Data("{\"apiKey\":\"\(token)\"}".utf8).write(to: root.appendingPathComponent("settings.json"))
    try Data("{\"access_token\":\"\(token)\"}".utf8).write(to: root.appendingPathComponent("oauth_creds.json"))
    return root
}

private func adapter(_ root: URL) -> GeminiAdapter { GeminiAdapter(additionalRoots: [root], includeDefaultRoots: false) }
private func install(_ root: URL) -> AgentInstallation {
    AgentInstallation(adapterID: GeminiStores.adapterID, rootURL: root, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }

@Suite struct GeminiAdapterTests {
    @Test func enumerationClaimsStoresAndFlagsUnknown() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, gaps) = try await adapter(root).enumerateStores(installation: install(root))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["chats"]?.present == true)
        #expect(present["logs"]?.present == true)
        #expect(present["checkpoints"]?.present == true)
        #expect(present["context"]?.present == true)
        #expect(present["settings"]?.tier == .excluded)
        #expect(present["credentials"]?.present == true)
        #expect(present["credentials"]?.capabilities.isEmpty == true)
        #expect(gaps.contains { $0.reason == .unknownStore && $0.path.hasSuffix("weird-thing") })
    }

    @Test func scanFindsSecretsAcrossStoresButNotExcluded() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let storeIDs = Set(report.occurrences.map(\.storeID.rawValue))
        #expect(storeIDs.isSuperset(of: ["chats", "logs", "checkpoints", "context"]))
        #expect(!storeIDs.contains("settings"))
        #expect(!storeIDs.contains("credentials"))
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }

    @Test func redactsAChatSecretAndRecordStillParses() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("tmp/hash1/chats/session-1.jsonl")
        // Make it inactive (older than the activity window) so redaction isn't deferred.
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -3600)], ofItemAtPath: file.path)

        let a = adapter(root)
        let engine = ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let redaction = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let (_, result) = try await redaction.redact(report: report, fingerprints: [gh.fingerprint])
        #expect(result.appliedCount >= 1)

        let after = try String(contentsOf: file, encoding: .utf8)
        #expect(!after.contains(token))
        let firstLine = try #require(after.split(separator: "\n").first)
        #expect((try? JSONSerialization.jsonObject(with: Data(firstLine.utf8))) != nil)
    }

    @Test func jsonlDeltaScansOnlyNewLines() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let a = adapter(root)
        let file = root.appendingPathComponent("tmp/hash1/chats/session-1.jsonl")
        let artifact0 = Artifact(url: file, storeID: GeminiStores.chats, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let first = try await a.extractDelta(artifact: artifact0, from: nil)
        #expect(first.scannedFromOffset == 0)

        // Append a new record, then delta-scan from the first cursor.
        let fh = try FileHandle(forWritingTo: file)
        try fh.seekToEnd()
        try fh.write(contentsOf: Data("{\"role\":\"user\",\"parts\":[{\"text\":\"second ghp_FAKEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}\n".utf8))
        try fh.close()
        let artifact1 = Artifact(url: file, storeID: GeminiStores.chats, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let delta = try await a.extractDelta(artifact: artifact1, from: first.newCursor)
        #expect(delta.scannedFromOffset == first.newCursor.lastScanOffset)   // resumed, didn't rescan line 1
        #expect(delta.content.regions.contains { $0.text.contains("second") })
        #expect(!delta.content.regions.contains { $0.text.contains("use ") })
    }
}
