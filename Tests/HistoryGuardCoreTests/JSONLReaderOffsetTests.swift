import Foundation
import Testing
import HistoryGuardCore

@Suite struct JSONLReaderOffsetTests {
    func writeTemp(_ s: String) throws -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".jsonl")
        try Data(s.utf8).write(to: u)
        return u
    }

    @Test func readsFromOffsetWithAbsoluteOffsets() throws {
        let url = try writeTemp("{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n")
        // Line 1 "{\"a\":1}\n" is 8 bytes, so the 2nd line begins at offset 8.
        var lines: [(index: Int, offset: Int, text: String)] = []
        let summary = try JSONLReader().forEachLine(at: url, from: 8) { line in
            lines.append((line.index, line.offset, String(decoding: line.bytes, as: UTF8.self)))
        }
        #expect(lines.map(\.text) == ["{\"b\":2}", "{\"c\":3}"])
        #expect(lines.map(\.offset) == [8, 16])   // absolute file offsets
        #expect(summary.bytesRead == 16)          // bytes from offset 8 to EOF
    }

    @Test func partialFinalLineIsTruncatedTail() throws {
        let url = try writeTemp("{\"a\":1}\n{\"b\":2")   // no trailing newline
        var tail: JSONLLine?
        _ = try JSONLReader().forEachLine(at: url, from: 0) { if $0.isTruncatedTail { tail = $0 } }
        #expect(tail?.offset == 8)
        #expect(tail?.isTruncatedTail == true)
    }
}
