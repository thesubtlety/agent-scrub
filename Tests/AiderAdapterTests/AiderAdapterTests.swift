import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import AiderAdapter

private let token = "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"

/// A synthetic repo directory holding Aider history files. All secret values are clearly FAKE.
private func makeRepo() throws -> URL {
    let fm = FileManager.default
    let repo = fm.temporaryDirectory.appendingPathComponent("aider-repo-\(UUID().uuidString)")
    try fm.createDirectory(at: repo, withIntermediateDirectories: true)
    try Data("# aider chat history\n\n#### fix it\n> use \(token) to auth\n".utf8)
        .write(to: repo.appendingPathComponent(".aider.chat.history.md"))
    try Data("fix the bug with \(token)\nunrelated prompt line\n".utf8)
        .write(to: repo.appendingPathComponent(".aider.input.history"))
    try Data("some unknown aider variant holding \(token)".utf8)
        .write(to: repo.appendingPathComponent(".aider.weird"))                    // unknown .aider.* → gap
    try fm.createDirectory(at: repo.appendingPathComponent(".aider.tags.cache.v4"), // excluded cache
                           withIntermediateDirectories: true)
    return repo
}

private func adapter() -> AiderAdapter { AiderAdapter(includeDefaultRoots: false) }
private func install(_ repo: URL) -> AgentInstallation {
    AgentInstallation(adapterID: AiderStores.adapterID, rootURL: repo, version: nil)
}
private func scanner() throws -> SecretScanner { SecretScanner(catalog: try RuleCatalog.bundled()) }
private func fp() -> Fingerprinter { Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))) }

@Suite struct AiderAdapterTests {
    @Test func discoveryFindsReposAndSkipsDenylisted() async throws {
        let fm = FileManager.default
        let searchRoot = fm.temporaryDirectory.appendingPathComponent("aider-search-\(UUID().uuidString)")
        let good = searchRoot.appendingPathComponent("code/myrepo")
        let buried = searchRoot.appendingPathComponent("code/node_modules/pkg/vendored")
        try fm.createDirectory(at: good, withIntermediateDirectories: true)
        try fm.createDirectory(at: buried, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: good.appendingPathComponent(".aider.input.history"))
        try Data("x".utf8).write(to: buried.appendingPathComponent(".aider.input.history"))
        defer { try? fm.removeItem(at: searchRoot) }

        let installs = await AiderAdapter(additionalRoots: [searchRoot], includeDefaultRoots: false).discoverInstallations()
        let paths = Set(installs.map { $0.rootURL.resolvingSymlinksInPath().standardizedFileURL.path })
        #expect(paths.contains(good.resolvingSymlinksInPath().standardizedFileURL.path))
        #expect(!paths.contains { $0.contains("node_modules") })   // denylisted dir never descended
    }

    @Test func enumerationClaimsStoresAndFlagsUnknown() async throws {
        let repo = try makeRepo(); defer { try? FileManager.default.removeItem(at: repo) }
        let (stores, gaps) = try await adapter().enumerateStores(installation: install(repo))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })
        #expect(present["chat-history"]?.present == true)
        #expect(present["input-history"]?.present == true)
        #expect(present["llm-history"]?.present == false)              // not created
        #expect(present["tags-cache"]?.tier == .excluded)
        #expect(present["tags-cache"]?.capabilities.isEmpty == true)
        #expect(gaps.contains { $0.reason == .unknownStore && $0.path.hasSuffix(".aider.weird") })
    }

    @Test func scanFindsSecretsButNotExcluded() async throws {
        let repo = try makeRepo(); defer { try? FileManager.default.removeItem(at: repo) }
        let engine = ScanEngine(adapter: adapter(), scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(repo))
        let storeIDs = Set(report.occurrences.map(\.storeID.rawValue))
        #expect(storeIDs.isSuperset(of: ["chat-history", "input-history"]))
        #expect(!storeIDs.contains("tags-cache"))
        #expect(report.secrets.contains { $0.kind == .githubToken })
    }

    @Test func redactsAnInputHistorySecret() async throws {
        let repo = try makeRepo(); defer { try? FileManager.default.removeItem(at: repo) }
        let fm = FileManager.default
        // Make the history files inactive (older than the activity window) so redaction isn't deferred.
        for name in [".aider.input.history", ".aider.chat.history.md"] {
            try fm.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -3600)],
                                 ofItemAtPath: repo.appendingPathComponent(name).path)
        }
        let a = adapter()
        let engine = ScanEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let report = try await engine.scan(installation: install(repo))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let redaction = RedactionEngine(adapter: a, scanner: try scanner(), fingerprinter: fp())
        let (_, result) = try await redaction.redact(report: report, fingerprints: [gh.fingerprint])
        #expect(result.appliedCount >= 1)

        let after = try String(contentsOf: repo.appendingPathComponent(".aider.input.history"), encoding: .utf8)
        #expect(!after.contains(token))
        #expect(after.contains("unrelated prompt line"))   // the rest of the file is intact
    }
}
