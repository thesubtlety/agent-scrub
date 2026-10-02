import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import ClineAdapter

private let token = "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"

/// A legacy globalStorage layout (saoudrizwan.claude-dev). All secret values are clearly FAKE.
private func makeLegacyRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("cline-legacy-\(UUID().uuidString)")
    let task = root.appendingPathComponent("tasks/task1")
    try fm.createDirectory(at: task, withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("state"), withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("checkpoints"), withIntermediateDirectories: true)
    try fm.createDirectory(at: root.appendingPathComponent("weird-thing"), withIntermediateDirectories: true)

    try Data("[{\"role\":\"user\",\"content\":\"use \(token) now\"}]".utf8)
        .write(to: task.appendingPathComponent("api_conversation_history.json"))
    try Data("[{\"type\":\"say\",\"text\":\"shown \(token)\"}]".utf8)
        .write(to: task.appendingPathComponent("ui_messages.json"))
    try Data("{\"taskHistory\":[{\"task\":\"did \(token)\"}]}".utf8)
        .write(to: root.appendingPathComponent("state/taskHistory.json"))
    // Checkpoints are extended-tier: a secret here must NOT be found by a default scan.
    try Data("{\"snapshot\":\"\(token)\"}".utf8).write(to: root.appendingPathComponent("checkpoints/snap.json"))
    // Excluded config — a secret here must never be scanned.
    try Data("{\"apiKey\":\"\(token)\"}".utf8).write(to: root.appendingPathComponent("settings.json"))
    return root
}

/// An SDK-era ~/.cline layout.
private func makeSDKRoot() throws -> URL {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("cline-sdk-\(UUID().uuidString)")
    let sess = root.appendingPathComponent("data/sessions/s1")
    try fm.createDirectory(at: sess, withIntermediateDirectories: true)
    try Data("[{\"role\":\"user\",\"content\":\"use \(token) now\"}]".utf8)
        .write(to: sess.appendingPathComponent("s1.messages.json"))
    try Data("{\"id\":\"s1\"}".utf8).write(to: sess.appendingPathComponent("s1.json"))
    return root
}

private func adapter(_ root: URL) -> ClineAdapter { ClineAdapter(additionalRoots: [root], includeDefaultRoots: false) }
private func install(_ root: URL) -> AgentInstallation {
    AgentInstallation(adapterID: ClineStores.adapterID, rootURL: root, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }

@Suite struct ClineAdapterTests {
    @Test func legacyEnumerationClaimsStoresAndFlagsUnknown() async throws {
        let root = try makeLegacyRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, gaps) = try await adapter(root).enumerateStores(installation: install(root))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["conversations"]?.present == true)
        #expect(present["ui-messages"]?.present == true)
        #expect(present["task-history"]?.present == true)
        #expect(present["checkpoints"]?.tier == .extended)
        #expect(present["settings"]?.tier == .excluded)
        #expect(present["settings"]?.capabilities.isEmpty == true)
        #expect(gaps.contains { $0.reason == .unknownStore && $0.path.hasSuffix("weird-thing") })
    }

    @Test func scanFindsContentButNotExcludedOrExtended() async throws {
        let root = try makeLegacyRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let storeIDs = Set(report.occurrences.map(\.storeID.rawValue))
        #expect(storeIDs.isSuperset(of: ["conversations", "ui-messages", "task-history"]))
        #expect(!storeIDs.contains("settings"))      // excluded
        #expect(!storeIDs.contains("checkpoints"))   // extended, off by default
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }

    @Test func redactsAConversationSecretAndJSONStillParses() async throws {
        let root = try makeLegacyRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("tasks/task1/api_conversation_history.json")
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -3600)], ofItemAtPath: file.path)

        let a = adapter(root)
        let engine = ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let redaction = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let (_, result) = try await redaction.redact(report: report, fingerprints: [gh.fingerprint])
        #expect(result.appliedCount >= 1)

        let after = try Data(contentsOf: file)
        #expect(!String(decoding: after, as: UTF8.self).contains(token))
        #expect((try? JSONSerialization.jsonObject(with: after)) != nil)   // still valid JSON
    }

    @Test func sdkSessionsAreEnumeratedAndScanned() async throws {
        let root = try makeSDKRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let (stores, _) = try await adapter(root).enumerateStores(installation: install(root))
        #expect(stores.first { $0.id.rawValue == "sessions" }?.present == true)

        let engine = ScanEngine(adapter: adapter(root), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(root))
        #expect(report.occurrences.contains { $0.storeID.rawValue == "sessions" })
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }
}
