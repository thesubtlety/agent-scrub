import Foundation
import Testing
import HistoryGuardCore
import ClaudeCodeAdapter
import SecretDetection

@Suite struct RescanArtifactTests {
    func engine(_ adapter: ClaudeCodeAdapter) throws -> ScanEngine {
        ScanEngine(adapter: adapter,
                   scanner: SecretScanner(catalog: try RuleCatalog.bundled()),
                   fingerprinter: Fingerprinter(key: InstallationKey.random()))
    }

    @Test func fullRescanFindsSeededToken() async throws {
        // A one-line JSONL transcript with a synthetic GitHub token (valid checksum) in a JSON string.
        let root = try TempTree.claudeRootWithTranscript(
            line: #"{"type":"user","message":{"content":"please use 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 here"}}"#)
        defer { try? FileManager.default.removeItem(at: root) }
        let adapter = ClaudeCodeAdapter(additionalRoots: [root], includeDefaultRoots: false)
        let inst = try #require(await adapter.discoverInstallations().first)
        let (stores, _) = try await adapter.enumerateStores(installation: inst)
        // Find the seeded transcript across whatever store enumerates it — no reliance on internal store ids.
        var artifact: Artifact?
        for store in stores where store.present {
            if let a = try await adapter.enumerateArtifacts(store: store, cursor: nil)
                .artifacts.first(where: { $0.kind == .jsonl }) { artifact = a; break }
        }
        let a = try #require(artifact)

        let delta = try await engine(adapter).rescanArtifact(a, cursor: nil)
        #expect(delta.findings.count == 1)
        #expect(delta.scannedFromOffset == 0)          // full scan
        #expect(delta.newCursor.lastScanOffset > 0)
    }
}
