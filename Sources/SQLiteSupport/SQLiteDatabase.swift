import CSQLite
import Foundation

public enum SQLiteError: Error, CustomStringConvertible {
    case open(String)
    case prepare(String, sql: String)
    case step(String)
    case busy

    public var description: String {
        switch self {
        case let .open(m): "open: \(m)"
        case let .prepare(m, sql): "prepare: \(m) [\(sql)]"
        case let .step(m): "step: \(m)"
        case .busy: "database is busy"
        }
    }
}

public enum SQLiteValue: Hashable, Sendable {
    case null
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)

    public var text: String? { if case let .text(s) = self { return s }; return nil }
    public var integer: Int64? { if case let .integer(i) = self { return i }; return nil }
}

public struct SQLiteColumn: Hashable, Sendable {
    public let name: String
    public let declaredType: String
}

/// Thin, synchronous wrapper over the C API. One connection per instance; not thread-safe. Opened read-only by
/// default so scanning can never mutate an agent's database.
public final class SQLiteDatabase {
    let db: OpaquePointer
    /// Whether this connection was opened read-only. A read-only connection cannot read a live WAL, so callers use
    /// this to tell a full-coverage read from one that may have missed uncheckpointed rows (see `openForReading`).
    public let isReadOnly: Bool

    public init(path: String, readOnly: Bool = true, create: Bool = false, busyTimeoutMs: Int32 = 2000) throws {
        var handle: OpaquePointer?
        let flags = readOnly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0))
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let h = handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "rc \(rc)"
            if let h = handle { sqlite3_close_v2(h) }
            throw SQLiteError.open(msg)
        }
        db = h
        isReadOnly = readOnly
        sqlite3_busy_timeout(db, busyTimeoutMs)
    }

    /// Whether the database at `path` has a `-wal` sidecar holding committed frames. A WAL file with only its
    /// 32-byte header (size ≤ 32) — including an empty one a read connection may have just created — holds no
    /// frames and is not evidence that anything is actively using the database.
    public static func hasLiveWAL(forDBAt path: String) -> Bool {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path + "-wal")
        return (attrs?[.size] as? UInt64 ?? 0) > 32
    }

    /// Open a (possibly live, WAL-mode) database for reading. A read-only connection can't read a WAL that another
    /// process is actively writing — it sees only the pre-WAL main file, missing the latest rows. So open
    /// read-write for `-wal`/`-shm` access, then:
    ///   - `PRAGMA query_only` forbids every data-change statement, and
    ///   - `NO_CKPT_ON_CLOSE` forbids the implicit checkpoint SQLite would otherwise run when our connection is the
    ///     last to close a WAL database — without it, merely scanning a DB with stale `-wal` frames (editor
    ///     force-quit/crashed) would rewrite the main file and bump its mtime. `query_only` does NOT stop that.
    /// Together these make the open strictly non-mutating. If the read-write open fails (read-only mount or
    /// permissions), fall back to read-only (which may miss live WAL data).
    public static func openForReading(path: String, busyTimeoutMs: Int32 = 1500) -> SQLiteDatabase? {
        if let db = try? SQLiteDatabase(path: path, readOnly: false, busyTimeoutMs: busyTimeoutMs) {
            db.disableCheckpointOnClose()
            try? db.execute("PRAGMA query_only = ON")
            return db
        }
        return try? SQLiteDatabase(path: path)
    }

    /// Stop SQLite from checkpointing the WAL into the main file when this connection closes. See `openForReading`.
    func disableCheckpointOnClose() { _ = hg_sqlite_disable_checkpoint_on_close(db) }

    deinit { sqlite3_close_v2(db) }

    public func tables() throws -> [String] {
        try query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .compactMap { $0["name"]?.text }
    }

    public func columns(of table: String) throws -> [SQLiteColumn] {
        try query("PRAGMA table_info(\(quoteIdentifier(table)))").map {
            SQLiteColumn(name: $0["name"]?.text ?? "", declaredType: ($0["type"]?.text ?? "").uppercased())
        }
    }

    /// A stable digest of the schema (table and column names and declared types) for known/unknown classification.
    public func schemaSignature() throws -> [String: [String]] {
        var out: [String: [String]] = [:]
        for t in try tables() { out[t] = try columns(of: t).map { "\($0.name):\($0.declaredType)" } }
        return out
    }

    public func integrityOK() throws -> Bool {
        try query("PRAGMA integrity_check").first?["integrity_check"]?.text == "ok"
    }

    public func quoteIdentifier(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }

    /// Runs a statement and returns every row as a name → value dictionary. Parameters bind positionally.
    @discardableResult
    public func query(_ sql: String, _ params: [SQLiteValue] = []) throws -> [[String: SQLiteValue]] {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let st = stmt else {
            throw SQLiteError.prepare(String(cString: sqlite3_errmsg(db)), sql: sql)
        }
        defer { sqlite3_finalize(st) }
        for (i, p) in params.enumerated() { bind(p, at: Int32(i + 1), st) }

        var rows: [[String: SQLiteValue]] = []
        let count = sqlite3_column_count(st)
        let names = (0..<count).map { String(cString: sqlite3_column_name(st, $0)) }
        while true {
            let rc = sqlite3_step(st)
            if rc == SQLITE_ROW {
                var row: [String: SQLiteValue] = [:]
                for i in 0..<count { row[names[Int(i)]] = value(at: i, st) }
                rows.append(row)
            } else if rc == SQLITE_DONE {
                break
            } else if rc == SQLITE_BUSY {
                throw SQLiteError.busy
            } else {
                throw SQLiteError.step(String(cString: sqlite3_errmsg(db)))
            }
        }
        return rows
    }

    /// Streams rows one at a time so a large table is never held in memory.
    public func forEachRow(_ sql: String, _ params: [SQLiteValue] = [], _ body: ([String: SQLiteValue]) throws -> Void) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let st = stmt else {
            throw SQLiteError.prepare(String(cString: sqlite3_errmsg(db)), sql: sql)
        }
        defer { sqlite3_finalize(st) }
        for (i, p) in params.enumerated() { bind(p, at: Int32(i + 1), st) }
        let count = sqlite3_column_count(st)
        let names = (0..<count).map { String(cString: sqlite3_column_name(st, $0)) }
        while true {
            let rc = sqlite3_step(st)
            if rc == SQLITE_ROW {
                var row: [String: SQLiteValue] = [:]
                for i in 0..<count { row[names[Int(i)]] = value(at: i, st) }
                try body(row)
            } else if rc == SQLITE_DONE { return }
            else if rc == SQLITE_BUSY { throw SQLiteError.busy }
            else { throw SQLiteError.step(String(cString: sqlite3_errmsg(db))) }
        }
    }

    public func execute(_ sql: String, _ params: [SQLiteValue] = []) throws {
        _ = try query(sql, params)
    }

    public var changes: Int { Int(sqlite3_changes(db)) }

    func bind(_ v: SQLiteValue, at i: Int32, _ st: OpaquePointer) {
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        switch v {
        case .null: sqlite3_bind_null(st, i)
        case let .integer(n): sqlite3_bind_int64(st, i, n)
        case let .real(d): sqlite3_bind_double(st, i, d)
        case let .text(s): sqlite3_bind_text(st, i, s, -1, transient)
        case let .blob(d): d.withUnsafeBytes { sqlite3_bind_blob(st, i, $0.baseAddress, Int32(d.count), transient) }
        }
    }

    func value(at i: Int32, _ st: OpaquePointer) -> SQLiteValue {
        switch sqlite3_column_type(st, i) {
        case SQLITE_INTEGER: return .integer(sqlite3_column_int64(st, i))
        case SQLITE_FLOAT: return .real(sqlite3_column_double(st, i))
        case SQLITE_TEXT: return .text(String(cString: sqlite3_column_text(st, i)))
        case SQLITE_BLOB:
            let n = Int(sqlite3_column_bytes(st, i))
            guard n > 0, let p = sqlite3_column_blob(st, i) else { return .blob(Data()) }
            return .blob(Data(bytes: p, count: n))
        default: return .null
        }
    }
}
