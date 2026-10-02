import Foundation
import HistoryGuardCore
import SQLiteSupport

public struct AuditEvent: Sendable, Equatable {
    public let ts: Date
    public let kind: String
    public let adapterID: String?
    public let storeID: String?
    public let fingerprintPrefix: String?
    public let artifactID: String?
    public let message: String
    public init(ts: Date, kind: String, adapterID: String?, storeID: String?,
                fingerprintPrefix: String?, artifactID: String?, message: String) {
        self.ts = ts; self.kind = kind; self.adapterID = adapterID; self.storeID = storeID
        self.fingerprintPrefix = fingerprintPrefix; self.artifactID = artifactID; self.message = message
    }
}

/// One SQLite file holding per-artifact scan cursors and an audit event log. Never stores secret
/// plaintext: events keep only a fingerprint prefix. Not thread-safe; the MonitorService actor owns it.
public final class StateStore {
    private let db: SQLiteDatabase

    public init(url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        db = try SQLiteDatabase(path: url.path, readOnly: false, create: true)
        // Restrict to the owner: the DB (and its WAL/SHM siblings in the same dir) holds masked displays and
        // paths. 0700 on the directory keeps the WAL/SHM private; 0600 on the file itself for good measure.
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.deletingLastPathComponent().path)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        try db.execute("PRAGMA journal_mode=WAL")
        try db.execute("""
            CREATE TABLE IF NOT EXISTS scan_cursors (
                path TEXT PRIMARY KEY, adapter_id TEXT NOT NULL, store_id TEXT NOT NULL,
                device INTEGER, inode INTEGER, size INTEGER NOT NULL,
                mtime REAL NOT NULL, last_scan_offset INTEGER NOT NULL, updated_at REAL NOT NULL)
            """)
        try db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL,
                adapter_id TEXT, store_id TEXT, fingerprint_prefix TEXT, artifact_id TEXT, message TEXT NOT NULL)
            """)
        // Persisted findings so a relaunch loads instantly and rescans only changed files. The stored JSON is
        // the Codable SecretIdentity/SecretOccurrence, which carry no secret plaintext (fingerprints + metadata).
        try db.execute("CREATE TABLE IF NOT EXISTS secrets (fingerprint TEXT PRIMARY KEY, identity_json BLOB NOT NULL)")
        try db.execute("""
            CREATE TABLE IF NOT EXISTS occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_path TEXT NOT NULL,
                fingerprint TEXT NOT NULL, occurrence_json BLOB NOT NULL)
            """)
        try db.execute("CREATE INDEX IF NOT EXISTS idx_occ_path ON occurrences(artifact_path)")
        try db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    }

    public func metaGet(_ key: String) throws -> String? {
        try db.query("SELECT value FROM meta WHERE key = ?", [.text(key)]).first?["value"]?.text
    }

    public func metaSet(_ key: String, _ value: String) throws {
        try db.execute("INSERT INTO meta (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       [.text(key), .text(value)])
    }

    /// Drop every persisted finding and scan cursor so the next reconcile rebuilds them from scratch. Used when
    /// the installation key changes: fingerprints are keyed by it, so stored findings no longer match live scans.
    public func clearFindings() throws {
        try db.execute("DELETE FROM occurrences")
        try db.execute("DELETE FROM secrets")
        try db.execute("DELETE FROM scan_cursors")
    }

    public func loadCursor(path: String) throws -> ScanCursor? {
        guard let r = try db.query("SELECT device, inode, size, mtime, last_scan_offset FROM scan_cursors WHERE path = ?",
                                   [.text(path)]).first else { return nil }
        let id = FileIdentity(device: r["device"]?.integer.map { UInt64(bitPattern: $0) },
                              inode: r["inode"]?.integer.map { UInt64(bitPattern: $0) },
                              size: UInt64(bitPattern: r["size"]?.integer ?? 0),
                              modified: Date(timeIntervalSince1970: doubleOf(r["mtime"])))
        return ScanCursor(fileIdentity: id, lastScanOffset: UInt64(r["last_scan_offset"]?.integer ?? 0))
    }

    public func saveCursor(path: String, adapterID: String, storeID: String, _ c: ScanCursor) throws {
        try db.execute("""
            INSERT INTO scan_cursors (path, adapter_id, store_id, device, inode, size, mtime, last_scan_offset, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(path) DO UPDATE SET adapter_id=excluded.adapter_id, store_id=excluded.store_id,
                device=excluded.device, inode=excluded.inode, size=excluded.size, mtime=excluded.mtime,
                last_scan_offset=excluded.last_scan_offset, updated_at=excluded.updated_at
            """, [.text(path), .text(adapterID), .text(storeID),
                  intOrNull(c.fileIdentity.device), intOrNull(c.fileIdentity.inode),
                  .integer(Int64(bitPattern: c.fileIdentity.size)), .real(c.fileIdentity.modified.timeIntervalSince1970),
                  .integer(Int64(bitPattern: c.lastScanOffset)), .real(Date().timeIntervalSince1970)])
    }

    public func deleteCursor(path: String) throws {
        try db.execute("DELETE FROM scan_cursors WHERE path = ?", [.text(path)])
    }

    public func allCursorPaths() throws -> Set<String> {
        Set(try db.query("SELECT path FROM scan_cursors").compactMap { $0["path"]?.text })
    }

    public func append(_ e: AuditEvent) throws {
        try db.execute("INSERT INTO events (ts, kind, adapter_id, store_id, fingerprint_prefix, artifact_id, message) VALUES (?,?,?,?,?,?,?)",
                       [.real(e.ts.timeIntervalSince1970), .text(e.kind), textOrNull(e.adapterID),
                        textOrNull(e.storeID), textOrNull(e.fingerprintPrefix), textOrNull(e.artifactID), .text(e.message)])
    }

    public func recentEvents(limit: Int) throws -> [AuditEvent] {
        try db.query("SELECT ts, kind, adapter_id, store_id, fingerprint_prefix, artifact_id, message FROM events ORDER BY id DESC LIMIT ?",
                     [.integer(Int64(limit))]).map { r in
            AuditEvent(ts: Date(timeIntervalSince1970: doubleOf(r["ts"])), kind: r["kind"]?.text ?? "",
                       adapterID: r["adapter_id"]?.text, storeID: r["store_id"]?.text,
                       fingerprintPrefix: r["fingerprint_prefix"]?.text, artifactID: r["artifact_id"]?.text,
                       message: r["message"]?.text ?? "")
        }
    }

    // MARK: Persisted findings

    /// Replace the stored occurrences for one artifact (delete-then-insert, so a rescan overwrites cleanly).
    public func saveOccurrences(path: String, _ occurrences: [SecretOccurrence]) throws {
        try db.execute("DELETE FROM occurrences WHERE artifact_path = ?", [.text(path)])
        for o in occurrences {
            let json = try JSONEncoder().encode(o)
            try db.execute("INSERT INTO occurrences (artifact_path, fingerprint, occurrence_json) VALUES (?,?,?)",
                           [.text(path), .text(o.fingerprint.hex), .blob(json)])
        }
    }

    public func deleteOccurrences(path: String) throws {
        try db.execute("DELETE FROM occurrences WHERE artifact_path = ?", [.text(path)])
    }

    public func saveIdentity(_ identity: SecretIdentity) throws {
        let json = try JSONEncoder().encode(identity)
        try db.execute("""
            INSERT INTO secrets (fingerprint, identity_json) VALUES (?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET identity_json=excluded.identity_json
            """, [.text(identity.fingerprint.hex), .blob(json)])
    }

    /// All persisted occurrences grouped by artifact path.
    public func loadOccurrencesByPath() throws -> [String: [SecretOccurrence]] {
        var out: [String: [SecretOccurrence]] = [:]
        for r in try db.query("SELECT artifact_path, occurrence_json FROM occurrences") {
            guard let path = r["artifact_path"]?.text, case let .blob(data)? = r["occurrence_json"],
                  let o = try? JSONDecoder().decode(SecretOccurrence.self, from: data) else { continue }
            out[path, default: []].append(o)
        }
        return out
    }

    public func loadIdentities() throws -> [SecretFingerprint: SecretIdentity] {
        var out: [SecretFingerprint: SecretIdentity] = [:]
        for r in try db.query("SELECT identity_json FROM secrets") {
            guard case let .blob(data)? = r["identity_json"],
                  let id = try? JSONDecoder().decode(SecretIdentity.self, from: data) else { continue }
            out[id.fingerprint] = id
        }
        return out
    }

    private func textOrNull(_ s: String?) -> SQLiteValue { s.map { .text($0) } ?? .null }
    private func intOrNull(_ v: UInt64?) -> SQLiteValue { v.map { .integer(Int64(bitPattern: $0)) } ?? .null }
    private func doubleOf(_ v: SQLiteValue?) -> Double {
        if case let .real(d)? = v { return d }; if case let .integer(i)? = v { return Double(i) }; return 0
    }
}
