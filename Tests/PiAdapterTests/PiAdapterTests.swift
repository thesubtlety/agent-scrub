import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import PiAdapter

private let token = "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"

/// Build a synthetic ~/.pi tree. All secret values are clearly FAKE.
private func makeRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("pi-\(UUID().uuidString)")
    let proj = root.appendingPathComponent("agent/sessions/--Users-dev-proj--")
    try fm.createDirectory(at: proj, withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("weird-thing"), withIntermediateDirectories: true)

    try Data("{\"type\":\"user\",\"message\":{\"content\":\"use \(token) now\"}}\n".utf8)
        .write(to: proj.appendingPathComponent("20260101T120000_abc123.jsonl"))
    // Excluded store — carries a secret that must NOT be scanned.
    try Data("{\"apiKey\":\"\(token)\"}".utf8).write(to: root.appendingPathComponent("config.json"))
    return root
}

private func adapter(_ root: URL) -> PiAdapter { PiAdapter(additionalRoots: [root], includeDefaultRoots: false) }
private func install(_ root: URL) -> AgentInstallation {
    AgentInstallation(adapterID: PiStores.adapterID, rootURL: root, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }

@Suite struct PiAdapterTests {
    @Test func enumerationClaimsSessionsAndFlagsUnknown() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, gaps) = try await adapter(root).enumerateStores(installation: install(root))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["sessions"]?.present == true)
        #expect(present["config"]?.tier == .excluded)
        #expect(present["config"]?.capabilities.isEmpty == true)
        #expect(gaps.contains { $0.reason == .unknownStore && $0.path.hasSuffix("weird-thing") })
    }

    @Test func scanFindsSessionSecretButNotExcluded() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let storeIDs = Set(report.occurrences.map(\.storeID.rawValue))
        #expect(storeIDs.contains("sessions"))
        #expect(!storeIDs.contains("config"))
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }

    @Test func redactsASessionSecretAndRecordStillParses() async throws {
        let root = try makeRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("agent/sessions/--Users-dev-proj--/20260101T120000_abc123.jsonl")
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
        let file = root.appendingPathComponent("agent/sessions/--Users-dev-proj--/20260101T120000_abc123.jsonl")
        let artifact0 = Artifact(url: file, storeID: PiStores.sessions, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let first = try await a.extractDelta(artifact: artifact0, from: nil)
        #expect(first.scannedFromOffset == 0)

        let fh = try FileHandle(forWritingTo: file)
        try fh.seekToEnd()
        try fh.write(contentsOf: Data("{\"type\":\"user\",\"message\":{\"content\":\"second ghp_FAKEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n".utf8))
        try fh.close()
        let artifact1 = Artifact(url: file, storeID: PiStores.sessions, kind: .jsonl, identity: try FileIdentity.read(at: file))
        let delta = try await a.extractDelta(artifact: artifact1, from: first.newCursor)
        #expect(delta.scannedFromOffset == first.newCursor.lastScanOffset)
        #expect(delta.content.regions.contains { $0.text.contains("second") })
        #expect(!delta.content.regions.contains { $0.text.contains("use ") })
    }
}
