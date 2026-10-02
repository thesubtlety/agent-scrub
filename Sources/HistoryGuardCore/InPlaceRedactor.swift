import Foundation

/// Same-length in-place overwrite for file-backed stores. Shared by every adapter so there is exactly one audited
/// write path. Per target: re-check inode and size, re-check the preimage, write, re-read, re-parse the touched
/// record, and restore the original bytes if the record no longer parses.
public struct InPlaceRedactor: Sendable {
    let walker = JSONStringWalker()
    public var maxRecordBytes = 64 << 20

    public init(maxRecordBytes: Int = 64 << 20) { self.maxRecordBytes = maxRecordBytes }

    public func apply(targets: [RedactionTarget], verifyPreimage: ([UInt8], RedactionTarget) -> Bool) -> [UUID: RedactionOutcome] {
        var outcomes: [UUID: RedactionOutcome] = [:]
        for (url, group) in Dictionary(grouping: targets, by: \.artifactURL) {
            let inPlace = group.filter { $0.preservesLength }
            let resizing = group.filter { !$0.preservesLength }
            if !inPlace.isEmpty {
                do {
                    let fh = try FileHandle(forUpdating: url)
                    defer { try? fh.close() }
                    for t in inPlace.sorted(by: { $0.range.lowerBound < $1.range.lowerBound }) {
                        outcomes[t.id] = applyOne(t, fh: fh, verifyPreimage: verifyPreimage)
                    }
                } catch {
                    for t in inPlace { outcomes[t.id] = .ioError(String(describing: error)) }
                }
            }
            // In-place edits are length-preserving, so the resize pass (which reads the whole file) sees correct
            // offsets afterwards.
            if !resizing.isEmpty { applyResizing(url: url, targets: resizing, verifyPreimage: verifyPreimage, into: &outcomes) }
        }
        return outcomes
    }

    /// Semantic rewrite: splice variable-length markers into a record whose value contains escapes, resizing the
    /// line. Each edit is validated (the record must still parse) with its original bytes restored on failure;
    /// the file is written once, atomically, only if at least one edit landed cleanly.
    func applyResizing(url: URL, targets: [RedactionTarget], verifyPreimage: ([UInt8], RedactionTarget) -> Bool,
                       into outcomes: inout [UUID: RedactionOutcome]) {
        guard let data = try? Data(contentsOf: url) else {
            for t in targets { outcomes[t.id] = .ioError("could not read \(url.lastPathComponent)") }; return
        }
        let identity = try? FileIdentity.read(at: url)
        var bytes = Array(data)
        var pending: [RedactionTarget] = []
        for t in targets {
            if let want = t.expectedIdentity.inode, let have = identity?.inode, want != have { outcomes[t.id] = .identityMismatch; continue }
            guard t.range.upperBound <= bytes.count else { outcomes[t.id] = .identityMismatch; continue }
            let current = Array(bytes[t.range])
            if current == t.replacement { outcomes[t.id] = .alreadyApplied; continue }
            if !verifyPreimage(current, t) { outcomes[t.id] = .preimageMismatch; continue }
            pending.append(t)
        }
        // Apply highest offset first so every not-yet-applied edit (and all content before it) keeps its offsets.
        var wrote = false
        for t in pending.sorted(by: { $0.range.lowerBound > $1.range.lowerBound }) {
            let saved = Array(bytes[t.range])
            bytes.replaceSubrange(t.range, with: t.replacement)
            if let failure = lineParseFailure(t.locator, in: bytes) {
                bytes.replaceSubrange(t.range.lowerBound..<(t.range.lowerBound + t.replacement.count), with: saved)
                outcomes[t.id] = .postCheckFailedAndRolledBack(failure)
            } else {
                outcomes[t.id] = .applied
                wrote = true
            }
        }
        if wrote {
            do { try Data(bytes).write(to: url, options: .atomic) }
            catch { for t in pending where outcomes[t.id] == .applied { outcomes[t.id] = .ioError(String(describing: error)) } }
        }
    }

    /// Does the record touched by a resize still parse? jsonl → just its line; json → the whole document.
    func lineParseFailure(_ locator: RecordLocator, in bytes: [UInt8]) -> String? {
        switch locator {
        case let .jsonlRecord(_, lineOffset, _):
            guard lineOffset <= bytes.count else { return "line offset past end of file" }
            var end = lineOffset
            while end < bytes.count, bytes[end] != 0x0A { end += 1 }
            do { _ = try walker.strings(in: Array(bytes[lineOffset..<end])); return nil }
            catch { return String(describing: error) }
        case .jsonDocument:
            do { _ = try walker.strings(in: Data(bytes)); return nil } catch { return String(describing: error) }
        case .plainFile, .sqliteCell:
            return nil
        }
    }

    func applyOne(_ t: RedactionTarget, fh: FileHandle, verifyPreimage: ([UInt8], RedactionTarget) -> Bool) -> RedactionOutcome {
        do {
            let now = try FileIdentity.read(at: t.artifactURL)
            if let want = t.expectedIdentity.inode, let have = now.inode, want != have { return .identityMismatch }
            if Int(now.size) < t.range.upperBound { return .identityMismatch }

            try fh.seek(toOffset: UInt64(t.range.lowerBound))
            guard let current = try fh.read(upToCount: t.range.count), current.count == t.range.count else { return .identityMismatch }
            if Array(current) == t.replacement { return .alreadyApplied }
            if !verifyPreimage(Array(current), t) { return .preimageMismatch }

            try fh.seek(toOffset: UInt64(t.range.lowerBound))
            try fh.write(contentsOf: Data(t.replacement))
            try fh.synchronize()

            try fh.seek(toOffset: UInt64(t.range.lowerBound))
            guard let after = try fh.read(upToCount: t.range.count), Array(after) == t.replacement else {
                return .ioError("re-read after write did not return the replacement")
            }
            if let failure = postCheck(t, fh: fh) {
                try fh.seek(toOffset: UInt64(t.range.lowerBound))
                try fh.write(contentsOf: current)
                try fh.synchronize()
                return .postCheckFailedAndRolledBack(failure)
            }
            return .applied
        } catch {
            return .ioError(String(describing: error))
        }
    }

    func postCheck(_ t: RedactionTarget, fh: FileHandle) -> String? {
        switch t.locator {
        case let .jsonlRecord(_, lineOffset, _):
            do {
                try fh.seek(toOffset: UInt64(lineOffset))
                var line: [UInt8] = []
                while line.count < maxRecordBytes {
                    guard let chunk = try fh.read(upToCount: 1 << 16), !chunk.isEmpty else { break }
                    if let nl = chunk.firstIndex(of: 0x0A) { line.append(contentsOf: chunk[..<nl]); break }
                    line.append(contentsOf: chunk)
                }
                _ = try walker.strings(in: line)
                return nil
            } catch { return String(describing: error) }
        case .jsonDocument:
            do { _ = try walker.strings(in: try Data(contentsOf: t.artifactURL)); return nil } catch { return String(describing: error) }
        case .plainFile, .sqliteCell:
            return nil
        }
    }
}
