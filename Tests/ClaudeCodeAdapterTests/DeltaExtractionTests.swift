import Foundation
import Testing
import HistoryGuardCore
import ClaudeCodeAdapter

@Suite struct DeltaExtractionTests {
    let adapter = ClaudeCodeAdapter(additionalRoots: [], includeDefaultRoots: false)

    // Values are >= 6 chars so the JSON string walker (default minimumLength 6) emits them as regions.
    // `{"a":"alphaAA"}\n` is 16 bytes; the second record begins at offset 16.
    func artifact(_ url: URL) throws -> Artifact {
        Artifact(url: url, storeID: StoreID("claude-transcripts"), kind: .jsonl,
                 identity: try FileIdentity.read(at: url))
    }
    func write(_ s: String) throws -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".jsonl")
        try Data(s.utf8).write(to: u); return u
    }

    // A partial final line is not scanned and does not advance the cursor.
    @Test func partialFinalLineBecomesGapAndHoldsCursor() async throws {
        let url = try write("{\"a\":\"alphaAA\"}\n{\"a\":\"brav")   // 2nd line unterminated
        let ex = try await adapter.extractDelta(artifact: try artifact(url), from: nil)
        #expect(ex.newCursor.lastScanOffset == 16)   // offset of the partial line's first byte
        #expect(ex.content.gaps.contains { if case .truncatedTail = $0.reason { return true }; return false })
        #expect(!ex.content.regions.contains { $0.text.contains("brav") })
    }

    // Only new complete lines are returned on the second call, resumed from the boundary.
    @Test func deltaReturnsOnlyNewLines() async throws {
        let url = try write("{\"a\":\"alphaAA\"}\n")
        let first = try await adapter.extractDelta(artifact: try artifact(url), from: nil)
        let fh = try FileHandle(forWritingTo: url); try fh.seekToEnd()
        try fh.write(contentsOf: Data("{\"a\":\"bravoBB\"}\n".utf8)); try fh.close()
        let a2 = try artifact(url)   // re-read identity (size grew)
        let ex = try await adapter.extractDelta(artifact: a2, from: first.newCursor)
        #expect(ex.content.regions.contains { $0.text == "bravoBB" })
        #expect(!ex.content.regions.contains { $0.text == "alphaAA" })   // line 1 not re-read
        #expect(ex.scannedFromOffset == 16)
        #expect(ex.newCursor.lastScanOffset == 32)
    }

    // Rotation/truncation: the file shrinks below the cursor, so it must be rescanned from 0.
    @Test func truncationForcesFullRescan() async throws {
        let url = try write("{\"a\":\"alphaAA\"}\n{\"a\":\"bravoBB\"}\n")
        let first = try await adapter.extractDelta(artifact: try artifact(url), from: nil)
        try Data("{\"a\":\"carrot9\"}\n".utf8).write(to: url)   // shorter rewrite
        let ex = try await adapter.extractDelta(artifact: try artifact(url), from: first.newCursor)
        #expect(ex.content.regions.contains { $0.text == "carrot9" })
        #expect(!ex.content.regions.contains { $0.text == "alphaAA" })
        #expect(ex.scannedFromOffset == 0)          // full rescan
        #expect(ex.newCursor.lastScanOffset == 16)
    }
}
