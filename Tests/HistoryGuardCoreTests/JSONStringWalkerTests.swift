import Foundation
import HistoryGuardCore
import Testing

@Suite struct JSONStringWalkerTests {
    let walker = JSONStringWalker(minimumLength: 1)

    @Test func pointersAndValues() throws {
        let doc = #"{"a":"hello","b":[1,"world",{"c":"nested"}],"d/e":"slash","f":null,"g":true,"h":-1.5e3}"#
        let out = try walker.strings(in: Array(doc.utf8))
        #expect(out.map(\.pointer) == ["/a", "/b/1", "/b/2/c", "/d~1e"])
        #expect(out.map(\.text) == ["hello", "world", "nested", "slash"])
    }

    @Test func bodyRangeSlicesTheSerializedBytes() throws {
        let doc = #"{"k":"value"}"#
        let bytes = Array(doc.utf8)
        let s = try #require(walker.strings(in: bytes).first)
        #expect(String(decoding: bytes[s.bodyRange], as: UTF8.self) == "value")
        #expect(s.hasEscapes == false)
        // plain ASCII: no map is materialised; the body range alone locates every byte
        #expect(s.offsetMap == nil)
    }

    @Test func escapesMapBackToEscapeStart() throws {
        // decoded: a"b<newline>c<euro>, with the euro written as a \\u escape (3 UTF-8 bytes once decoded)
        let doc = #"{"k":"a\"b\nc\u20ac"}"#
        let bytes = Array(doc.utf8)
        let s = try #require(walker.strings(in: bytes).first)
        #expect(s.text == "a\"b\nc€")
        #expect(s.hasEscapes)
        let map = try #require(s.offsetMap)
        let body = s.bodyRange.lowerBound
        // a
        #expect(map[0] == body + 0)
        // \" occupies serialized [1,3)
        #expect(map[1] == body + 1)
        // b
        #expect(map[2] == body + 3)
        // \n occupies [4,6)
        #expect(map[3] == body + 4)
        // c
        #expect(map[4] == body + 6)
        // euro = 3 decoded bytes all mapping to the \u escape start at 7
        #expect(map[5] == body + 7)
        #expect(map[6] == body + 7)
        #expect(map[7] == body + 7)
        #expect(map[8] == s.bodyRange.upperBound)
    }

    @Test func lateEscapeBackfillsIdentityPrefix() throws {
        let doc = #"{"k":"abcdef\tX"}"#
        let bytes = Array(doc.utf8)
        let s = try #require(walker.strings(in: bytes).first)
        let map = try #require(s.offsetMap)
        let body = s.bodyRange.lowerBound
        #expect(Array(map.prefix(6)) == (0..<6).map { body + $0 })
        #expect(map[6] == body + 6)   // \t escape start
        #expect(map[7] == body + 8)   // X after the two-byte escape
        #expect(map[8] == s.bodyRange.upperBound)
    }

    @Test func surrogatePairsDecode() throws {
        let doc = #"["😀"]"#
        let s = try #require(walker.strings(in: Array(doc.utf8)).first)
        #expect(s.text == "😀")
        #expect(s.offsetMap?.count == 5)
    }

    @Test func rawUTF8PassesThrough() throws {
        let doc = "{\"k\":\"café\"}"
        let s = try #require(walker.strings(in: Array(doc.utf8)).first)
        #expect(s.text == "café")
        #expect(s.hasEscapes)   // non-ASCII bytes flagged so feasibility checks look closer
        #expect(s.offsetMap?.count == s.text.utf8.count + 1)
    }

    @Test func rejectsTruncatedAndGarbage() {
        #expect(throws: JSONWalkError.self) { try walker.strings(in: Array(#"{"k":"unterminated"#.utf8)) }
        #expect(throws: JSONWalkError.self) { try walker.strings(in: Array(#"{"k":"v"} trailing"#.utf8)) }
        #expect(throws: JSONWalkError.self) { try walker.strings(in: Array(#"{"k":"bad \q escape"}"#.utf8)) }
    }

    @Test func minimumLengthFiltersShortStrings() throws {
        let out = try JSONStringWalker(minimumLength: 6).strings(in: Array(#"{"a":"short","b":"long enough"}"#.utf8))
        #expect(out.map(\.text) == ["long enough"])
    }

    @Test func contentRegionFeasibility() throws {
        let doc = #"{"k":"tok_ABCDEF\nrest"}"#
        let s = try #require(walker.strings(in: Array(doc.utf8)).first)
        let region = ContentRegion(text: s.text, locator: .jsonDocument(pointer: s.pointer), baseOffset: s.bodyRange.lowerBound,
                                   offsetMap: s.offsetMap, hasEscapes: s.hasEscapes)
        // "tok_ABCDEF" has no escapes inside -> can be patched in place
        #expect(region.feasibility(for: 0..<10) == .byteLengthPreserving)
        #expect(region.serializedRange(for: 0..<10) == s.bodyRange.lowerBound..<(s.bodyRange.lowerBound + 10))
        // a range spanning the \n escape cannot be patched byte-for-byte
        #expect(region.feasibility(for: 0..<12) == .requiresSemanticRewrite)
    }
}

@Suite struct JSONLReaderTests {
    func tmp(_ contents: String) throws -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("hg-\(UUID().uuidString).jsonl")
        try contents.write(to: u, atomically: true, encoding: .utf8)
        return u
    }

    @Test func linesOffsetsAndTruncatedTail() throws {
        let url = try tmp("{\"a\":1}\n{\"b\":22}\n{\"c\":\"tail")
        var lines: [JSONLLine] = []
        try JSONLReader(chunkSize: 5).forEachLine(at: url) { lines.append($0) }
        #expect(lines.count == 3)
        #expect(lines.map(\.offset) == [0, 8, 17])
        #expect(lines.map(\.isTruncatedTail) == [false, false, true])
        #expect(String(decoding: lines[1].bytes, as: UTF8.self) == "{\"b\":22}")
    }

    @Test func oversizeRecordIsReportedAndFollowingLinesStillDelivered() throws {
        let url = try tmp(String(repeating: "x", count: 100) + "\n{\"ok\":1}\n")
        var delivered: [String] = []
        let summary = try JSONLReader(chunkSize: 16, maxRecordBytes: 50).forEachLine(at: url) {
            delivered.append(String(decoding: $0.bytes, as: UTF8.self))
        }
        #expect(delivered == ["{\"ok\":1}"])
        #expect(summary.skippedOversize.count == 1)
        #expect(summary.skippedOversize.first?.line == 0)
        #expect(summary.skippedOversize.first?.offset == 0)
        #expect(summary.bytesRead == 110)
    }
}

@Suite struct TextChunkerTests {
    @Test func chunksOverlapAndAlignToUTF8() throws {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("hg-\(UUID().uuidString).txt")
        let text = String(repeating: "é", count: 3000) // 6000 bytes of 2-byte sequences
        try text.write(to: u, atomically: true, encoding: .utf8)
        var chunks: [TextChunker.Chunk] = []
        try TextChunker(chunkSize: 1001, overlap: 100).forEachChunk(at: u) { chunks.append($0) }
        #expect(chunks.count > 1)
        for c in chunks {
            #expect(String(bytes: c.bytes, encoding: .utf8) != nil, "chunk at \(c.offset) split a UTF-8 sequence")
        }
        // Reassembling from offsets reproduces the file.
        var rebuilt = [UInt8](repeating: 0, count: 6000)
        for c in chunks { for (i, b) in c.bytes.enumerated() { rebuilt[c.offset + i] = b } }
        #expect(rebuilt == Array(text.utf8))
    }
}

@Suite struct FingerprintTests {
    @Test func stableAndKeyDependent() {
        let k1 = InstallationKey(data: Data(repeating: 1, count: 32))
        let k2 = InstallationKey(data: Data(repeating: 2, count: 32))
        let a = Fingerprinter(key: k1).fingerprint(namespace: "githubToken", canonical: Data("x".utf8))
        let b = Fingerprinter(key: k1).fingerprint(namespace: "githubToken", canonical: Data("x".utf8))
        let c = Fingerprinter(key: k2).fingerprint(namespace: "githubToken", canonical: Data("x".utf8))
        let d = Fingerprinter(key: k1).fingerprint(namespace: "stripeKey", canonical: Data("x".utf8))
        #expect(a == b)
        #expect(a != c)
        #expect(a != d)
        #expect(a.shortHex.count == 8)
    }
}
