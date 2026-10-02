import Foundation

/// One physical line of a JSONL file.
public struct JSONLLine: Sendable {
    public let index: Int
    /// Byte offset of the first byte of the line in the file.
    public let offset: Int
    public let bytes: [UInt8]
    /// True when the line was not terminated by "\n" (file still being written, or truncated).
    public let isTruncatedTail: Bool
}

/// Summary of one pass over a JSONL file.
public struct JSONLReadSummary: Sendable {
    public var bytesRead: Int
    /// Records that exceeded `maxRecordBytes` and were skipped without being delivered.
    public var skippedOversize: [(line: Int, offset: Int)]
}

/// Streams a JSONL file line by line with bounded memory (one record at a time). Records larger than
/// `maxRecordBytes` are skipped and reported in the summary so the caller can record a coverage gap.
public struct JSONLReader: Sendable {
    public var chunkSize = 1 << 20
    public var maxRecordBytes = 64 << 20

    public init(chunkSize: Int = 1 << 20, maxRecordBytes: Int = 64 << 20) {
        self.chunkSize = chunkSize
        self.maxRecordBytes = maxRecordBytes
    }

    /// Calls `body` for each complete line. `body` may throw to abort.
    @discardableResult
    public func forEachLine(at url: URL, from startOffset: Int = 0, _ body: (JSONLLine) throws -> Void) throws -> JSONLReadSummary {
        let fh = try FileHandle(forReadingFrom: url)
        defer { try? fh.close() }
        if startOffset > 0 { try fh.seek(toOffset: UInt64(startOffset)) }

        var carry: [UInt8] = []
        var lineIndex = 0
        var fileOffset = startOffset      // offset of carry[0]
        var summary = JSONLReadSummary(bytesRead: 0, skippedOversize: [])
        var skippingOversize = false

        while true {
            let data = try fh.read(upToCount: chunkSize) ?? Data()
            if data.isEmpty { break }
            summary.bytesRead += data.count
            carry.append(contentsOf: data)

            var start = 0
            while let nl = carry[start...].firstIndex(of: 0x0A) {
                let lineBytes = Array(carry[start..<nl])
                if skippingOversize {
                    skippingOversize = false
                } else if lineBytes.count > maxRecordBytes {
                    summary.skippedOversize.append((lineIndex, fileOffset + start))
                } else {
                    try body(JSONLLine(index: lineIndex, offset: fileOffset + start, bytes: lineBytes, isTruncatedTail: false))
                }
                lineIndex += 1
                start = nl + 1
            }
            if start > 0 {
                carry.removeFirst(start)
                fileOffset += start
            }
            if carry.count > maxRecordBytes, !skippingOversize {
                // Discard the oversize partial record but keep counting offsets; report it once at its start.
                summary.skippedOversize.append((lineIndex, fileOffset))
                skippingOversize = true
            }
            if skippingOversize {
                fileOffset += carry.count
                carry.removeAll(keepingCapacity: true)
            }
        }
        if !carry.isEmpty, !skippingOversize {
            try body(JSONLLine(index: lineIndex, offset: fileOffset, bytes: carry, isTruncatedTail: true))
        }
        return summary
    }
}
