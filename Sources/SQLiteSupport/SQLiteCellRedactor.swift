import Foundation
import HistoryGuardCore

/// Applies same-length, in-place redactions to SQLite cells, one IMMEDIATE transaction per database. Each cell is
/// re-read inside the transaction, its preimage re-verified, rewritten with the same-length replacement (keeping the
/// original TEXT/BLOB type), checked by an adapter-supplied policy, and re-read after commit. Finishes with an
/// integrity check and a WAL checkpoint so no pre-redaction page lingers. Shared by every database-backed adapter
/// the way `InPlaceRedactor` is shared for files — one audited writer instead of a copy per adapter.
public struct SQLiteCellRedactor {
    /// Adapter-supplied behaviour. `busyWriter` names the writing app for busy messages ("Cursor", "Codex"). The
    /// closure says whether a cell must still parse as JSON after the rewrite — a text cell that was JSON, or a
    /// column the adapter's schema declares as JSON; a binary cell returns false (no text structure to preserve).
    public struct Policy {
        public let busyWriter: String
        public let mustStayParseableJSON: (_ target: RedactionTarget, _ originalBytes: [UInt8], _ wasBlob: Bool) -> Bool
        public init(busyWriter: String,
                    mustStayParseableJSON: @escaping (_ target: RedactionTarget, _ originalBytes: [UInt8], _ wasBlob: Bool) -> Bool) {
            self.busyWriter = busyWriter
            self.mustStayParseableJSON = mustStayParseableJSON
        }
    }

    let walker = JSONStringWalker()
    public init() {}

    /// A cell's raw bytes and whether the column held it as a BLOB (so a rewrite rebinds the same type).
    public static func cellBytes(_ v: SQLiteValue?) -> (bytes: [UInt8], isBlob: Bool)? {
        switch v {
        case let .text(s): return (Array(s.utf8), false)
        case let .blob(d): return (Array(d), true)
        default: return nil
        }
    }

    public func apply(_ targets: [RedactionTarget], verifyPreimage: ([UInt8], RedactionTarget) -> Bool, policy: Policy) -> [UUID: RedactionOutcome] {
        var outcomes: [UUID: RedactionOutcome] = [:]
        for (url, group) in Dictionary(grouping: targets, by: \.artifactURL) {
            outcomes.merge(applyOne(group, database: url, verifyPreimage: verifyPreimage, policy: policy)) { a, _ in a }
        }
        return outcomes
    }

    private func applyOne(_ targets: [RedactionTarget], database url: URL,
                          verifyPreimage: ([UInt8], RedactionTarget) -> Bool, policy: Policy) -> [UUID: RedactionOutcome] {
        var outcomes: [UUID: RedactionOutcome] = [:]
        let db: SQLiteDatabase
        do { db = try SQLiteDatabase(path: url.path, readOnly: false, busyTimeoutMs: 1500) } catch {
            for t in targets { outcomes[t.id] = .ioError(String(describing: error)) }
            return outcomes
        }
        do { try db.execute("BEGIN IMMEDIATE") } catch {
            let s = String(describing: error)
            let busy = { if case .busy? = error as? SQLiteError { return true }; return s.contains("locked") || s.contains("busy") }()
            for t in targets { outcomes[t.id] = .ioError(busy ? "database is busy (\(policy.busyWriter) is writing); will retry" : s) }
            return outcomes
        }
        var written: [RedactionTarget] = []
        for t in targets {
            guard case let .sqliteCell(table, rowid, column) = t.locator else { continue }
            let qt = db.quoteIdentifier(table), qc = db.quoteIdentifier(column)
            do {
                guard let originalValue = try db.query("SELECT \(qc) AS c FROM \(qt) WHERE rowid = ?", [.integer(rowid)]).first?["c"],
                      let (originalBytes, wasBlob) = Self.cellBytes(originalValue) else { outcomes[t.id] = .identityMismatch; continue }
                var bytes = originalBytes
                guard t.range.upperBound <= bytes.count else { outcomes[t.id] = .identityMismatch; continue }
                let current = Array(bytes[t.range])
                if current == t.replacement { outcomes[t.id] = .alreadyApplied; continue }
                guard verifyPreimage(current, t) else { outcomes[t.id] = .preimageMismatch; continue }
                bytes.replaceSubrange(t.range, with: t.replacement)
                guard bytes.count == originalBytes.count else { outcomes[t.id] = .ioError("cell rewrite must preserve length"); continue }
                if policy.mustStayParseableJSON(t, originalBytes, wasBlob), (try? walker.strings(in: bytes)) == nil {
                    outcomes[t.id] = .postCheckFailedAndRolledBack("cell would no longer parse as JSON"); continue
                }
                let newValue: SQLiteValue
                if wasBlob {
                    newValue = .blob(Data(bytes))
                } else {
                    guard let s = String(bytes: bytes, encoding: .utf8) else { outcomes[t.id] = .ioError("replacement produced invalid UTF-8"); continue }
                    newValue = .text(s)
                }
                try db.execute("UPDATE \(qt) SET \(qc) = ? WHERE rowid = ? AND \(qc) = ?", [newValue, .integer(rowid), originalValue])
                guard db.changes == 1 else { outcomes[t.id] = .preimageMismatch; continue }
                written.append(t)
            } catch {
                outcomes[t.id] = .ioError(String(describing: error))
            }
        }
        do { try db.execute("COMMIT") } catch {
            try? db.execute("ROLLBACK")
            for t in written { outcomes[t.id] = .ioError("commit failed: \(error)") }
            return outcomes
        }
        // Post-commit confirmation. The UPDATE already committed, so a read blip here must NOT unwrite it: only a
        // positive re-read of the wrong bytes contradicts the write; a failed re-read trusts the committed change.
        for t in written {
            guard case let .sqliteCell(table, rowid, column) = t.locator else { continue }
            guard let v = try? db.query("SELECT \(db.quoteIdentifier(column)) AS c FROM \(db.quoteIdentifier(table)) WHERE rowid = ?", [.integer(rowid)]).first?["c"],
                  let (bytes, _) = Self.cellBytes(v) else { outcomes[t.id] = .applied; continue }
            outcomes[t.id] = (t.range.upperBound <= bytes.count && Array(bytes[t.range]) == t.replacement)
                ? .applied : .ioError("re-read after commit did not return the replacement")
        }
        // A same-length API-level UPDATE cannot corrupt the B-tree integrity_check validates, and the check can't
        // roll back an already-committed change anyway — so only a definite `false` counts; a transient throw must
        // not relabel genuinely-applied cells as failures.
        if (try? db.integrityOK()) == false {
            for t in written where outcomes[t.id] == .applied { outcomes[t.id] = .ioError("integrity_check failed after write") }
        }
        _ = try? db.query("PRAGMA wal_checkpoint(TRUNCATE)")
        return outcomes
    }
}
