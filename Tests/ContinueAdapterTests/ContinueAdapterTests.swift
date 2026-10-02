import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import ContinueAdapter

private let token = "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"

/// Build a synthetic ~/.continue tree. All secret values are clearly FAKE.
private func makeRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("continue-\(UUID().uuidString)")
    let sessions = root.appendingPathComponent("sessions")
    let devData = root.appendingPathComponent("dev_data/0.2.0")
    let index = root.appendingPathComponent("index/lancedb")
    try fm.createDirectory(at: sessions, withIntermediateDirectories: true)
    try fm.createDirectory(at: devData, withIntermediateDirectories: true)
    try fm.createDirectory(at: index, withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("weird-thing"), withIntermediateDirectories: true)

    try Data("{\"history\":[{\"message\":{\"role\":\"user\",\"content\":\"use \(token) now\"}}],\"contextItems\":[]}".utf8)
        .write(to: sessions.appendingPathComponent("abc-123.json"))
    try Data("{\"sessions\":[{\"sessionId\":\"abc-123\",\"title\":\"work\"}]}".utf8)
        .write(to: sessions.appendingPathComponent("sessions.json"))
    try Data("{\"event\":\"chat\",\"prompt\":\"log \(token)\"}\n".utf8)
        .write(to: devData.appendingPathComponent("chatInteraction.jsonl"))
    // Excluded stores — carry a secret that must NOT be scanned.
    try Data("{\"embedding\":\"\(token)\"}".utf8).write(to: index.appendingPathComponent("data.json"))
    try Data("models:\n  - apiKey: \(token)\n".utf8).write(to: root.appendingPathComponent("config.yaml"))
    return root
}

private func adapter(_ root: URL) -> ContinueAdapter { ContinueAdapter(additionalRoots: [root], includeDefaultRoots: false) }
private func install(_ root: URL) -> AgentInstallation {
    AgentInstallation(adapterID: ContinueStores.adapterID, rootURL: root, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }

@Suite struct ContinueAdapterTests {
    @Test func enumerationClaimsStoresAndFlagsUnknown() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, gaps) = try await adapter(root).enumerateStores(installation: install(root))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["sessions"]?.present == true)
        #expect(present["dev-data"]?.present == true)
        #expect(present["index"]?.tier == .excluded)
        #expect(present["config"]?.tier == .excluded)
        #expect(present["config"]?.capabilities.isEmpty == true)
        #expect(gaps.contains { $0.reason == .unknownStore && $0.path.hasSuffix("weird-thing") })
    }

    @Test func scanFindsSecretsAcrossStoresButNotExcluded() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let storeIDs = Set(report.occurrences.map(\.storeID.rawValue))
        #expect(storeIDs.isSuperset(of: ["sessions", "dev-data"]))
        #expect(!storeIDs.contains("index"))
        #expect(!storeIDs.contains("config"))
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }

    @Test func redactsASessionSecretAndRecordStillParses() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("sessions/abc-123.json")
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
        #expect((try? JSONSerialization.jsonObject(with: Data(after.utf8))) != nil)   // whole doc still valid JSON
    }

    @Test func devDataJSONLDeltaScansOnlyNewLines() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let a = adapter(root)
        let file = root.appendingPathComponent("dev_data/0.2.0/chatInteraction.jsonl")
        let artifact0 = Artifact(url: file, storeID: ContinueStores.devData, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let first = try await a.extractDelta(artifact: artifact0, from: nil)
        #expect(first.scannedFromOffset == 0)

        let fh = try FileHandle(forWritingTo: file)
        try fh.seekToEnd()
        try fh.write(contentsOf: Data("{\"event\":\"chat\",\"prompt\":\"second ghp_FAKEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n".utf8))
        try fh.close()
        let artifact1 = Artifact(url: file, storeID: ContinueStores.devData, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let delta = try await a.extractDelta(artifact: artifact1, from: first.newCursor)
        #expect(delta.scannedFromOffset == first.newCursor.lastScanOffset)
        #expect(delta.content.regions.contains { $0.text.contains("second") })
        #expect(!delta.content.regions.contains { $0.text.contains("log ") })
    }
}
