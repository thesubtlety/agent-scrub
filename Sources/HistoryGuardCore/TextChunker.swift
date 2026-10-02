import Foundation

/// Reads a file in bounded, overlapping chunks aligned to UTF-8 boundaries so a secret that straddles a
/// chunk edge is fully contained in at least one chunk. Consumers dedupe by absolute offset.
public struct TextChunker: Sendable {
    public let chunkSize: Int
    public let overlap: Int

    public init(chunkSize: Int = 1 << 20, overlap: Int = 16 << 10) {
        precondition(overlap < chunkSize)
        self.chunkSize = chunkSize
        self.overlap = overlap
    }

    public struct Chunk: Sendable {
        /// Absolute byte offset of `bytes[0]` in the file.
        public let offset: Int
        public let bytes: [UInt8]
        public let isLast: Bool
    }

    /// Returns total bytes read. Never holds more than chunkSize + overlap bytes.
    @discardableResult
    public func forEachChunk(at url: URL, _ body: (Chunk) throws -> Void) throws -> Int {
        let fh = try FileHandle(forReadingFrom: url)
        defer { try? fh.close() }

        var carry: [UInt8] = []
        var carryOffset = 0
        var total = 0

        while true {
            let data = try fh.read(upToCount: chunkSize) ?? Data()
            let isLast = data.count < chunkSize
            if data.isEmpty && carry.isEmpty { break }
            total += data.count
            let buffer = carry + data

            var usable = buffer.count
            if !isLast {
                // Back off to a UTF-8 boundary so we never split a multi-byte sequence.
                var k = usable
                var steps = 0
                while k > 0, steps < 4, buffer[k - 1] & 0xC0 == 0x80 { k -= 1; steps += 1 }
                if k > 0, buffer[k - 1] & 0xC0 == 0xC0 { k -= 1 }
                usable = k
            }
            try body(Chunk(offset: carryOffset, bytes: Array(buffer[..<usable]), isLast: isLast))
            if isLast { break }

            let keepFrom = max(0, usable - overlap)
            carry = Array(buffer[keepFrom...])
            carryOffset += keepFrom
        }
        return total
    }
}
