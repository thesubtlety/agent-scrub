import Foundation
import Testing
@testable import SQLiteSupport

@Suite struct OpenForReadingTests {
    /// The guarantee the WAL-read change must not break: opening a database only to read it never rewrites the
    /// user's file. The dangerous case is a WAL database with un-checkpointed `-wal` frames and no other open
    /// connection (editor force-quit/crashed): SQLite would checkpoint on close. `openForReading` sets
    /// NO_CKPT_ON_CLOSE to forbid that — so the main file stays byte-for-byte identical, yet the WAL data is
    /// still read. Without the fix this test fails (the close checkpoints and the main file changes).
    @Test func readingAStaleWALLeavesTheFileByteIdentical() throws {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("sqlite-wal-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let secret = "SECRET_ONLY_IN_WAL_\(UUID().uuidString)"

        // Build a WAL DB whose row lives only in the -wal (autocheckpoint off, connection kept open so nothing
        // checkpoints), then copy the main file + -wal to a fresh path = a stale WAL at rest with no open connection.
        let live = dir.appendingPathComponent("live.db")
        let lc = try SQLiteDatabase(path: live.path, readOnly: false, create: true)
        try lc.execute("PRAGMA journal_mode=WAL")
        try lc.execute("PRAGMA wal_autocheckpoint=0")
        try lc.execute("CREATE TABLE t (v TEXT)")
        try lc.execute("INSERT INTO t (v) VALUES (?)", [.text(secret)])

        let rest = dir.appendingPathComponent("rest.db")
        try fm.copyItem(at: live, to: rest)
        try fm.copyItem(at: URL(fileURLWithPath: live.path + "-wal"), to: URL(fileURLWithPath: rest.path + "-wal"))
        // (no -shm copy: SQLite rebuilds it from the -wal on open)
        _ = lc   // keep the live connection open until after the copy, so its close can't checkpoint `live`

        // Preconditions: the data is in the -wal, not the main file.
        #expect(try Data(contentsOf: URL(fileURLWithPath: rest.path + "-wal")).count > 32)   // WAL header + frames
        #expect(!(try Data(contentsOf: rest).range(of: Data(secret.utf8)) != nil))

        let before = try Data(contentsOf: rest)

        // Scan it the way the adapters do: openForReading is the sole/last connection, so a close WOULD checkpoint.
        var handle: SQLiteDatabase? = SQLiteDatabase.openForReading(path: rest.path)
        let got = try #require(handle).query("SELECT v FROM t").first?["v"]?.text
        handle = nil   // deinit → sqlite3_close_v2; the fix forbids the checkpoint here

        #expect(got == secret)                                   // WAL data was actually read
        #expect(try Data(contentsOf: rest) == before)            // main file untouched — no checkpoint
    }

    /// A rollback-journal (DELETE-mode) database must not be converted to WAL or gain sidecar files just by reading.
    @Test func readingARollbackJournalDBCreatesNoSidecars() throws {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("sqlite-rj-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let db = dir.appendingPathComponent("rj.db")
        do {
            let c = try SQLiteDatabase(path: db.path, readOnly: false, create: true)
            try c.execute("CREATE TABLE t (v TEXT)")
            try c.execute("INSERT INTO t (v) VALUES ('x')")
            _ = c
        }
        let before = try Data(contentsOf: db)
        var handle: SQLiteDatabase? = SQLiteDatabase.openForReading(path: db.path)
        _ = try #require(handle).query("SELECT v FROM t").first?["v"]?.text
        handle = nil
        #expect(try Data(contentsOf: db) == before)
        #expect(!fm.fileExists(atPath: db.path + "-wal"))
        #expect(!fm.fileExists(atPath: db.path + "-shm"))
    }
}
