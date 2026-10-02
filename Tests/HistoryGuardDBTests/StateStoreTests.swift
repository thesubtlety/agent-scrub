import Foundation
import Testing
import HistoryGuardCore
@testable import HistoryGuardDB

@Suite struct StateStoreTests {
    func tempStore() throws -> (StateStore, URL) {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".sqlite")
        return (try StateStore(url: u), u)
    }

    @Test func cursorRoundTripAndDelete() throws {
        let (store, u) = try tempStore(); defer { try? FileManager.default.removeItem(at: u) }
        let id = FileIdentity(device: 1, inode: 42, size: 100, modified: Date(timeIntervalSince1970: 5))
        try store.saveCursor(path: "/a/b.jsonl", adapterID: "claude-code", storeID: "claude-transcripts",
                             ScanCursor(fileIdentity: id, lastScanOffset: 96))
        let back = try store.loadCursor(path: "/a/b.jsonl")
        #expect(back?.lastScanOffset == 96)
        #expect(back?.fileIdentity.inode == 42)
        let paths = try store.allCursorPaths()
        #expect(paths == ["/a/b.jsonl"])
        try store.deleteCursor(path: "/a/b.jsonl")
        let gone = try store.loadCursor(path: "/a/b.jsonl")
        #expect(gone == nil)
    }

    @Test func cursorUpsertReplaces() throws {
        let (store, u) = try tempStore(); defer { try? FileManager.default.removeItem(at: u) }
        let id = FileIdentity(device: 1, inode: 1, size: 10, modified: Date())
        try store.saveCursor(path: "/x", adapterID: "a", storeID: "s", ScanCursor(fileIdentity: id, lastScanOffset: 4))
        try store.saveCursor(path: "/x", adapterID: "a", storeID: "s", ScanCursor(fileIdentity: id, lastScanOffset: 8))
        let back = try store.loadCursor(path: "/x")
        #expect(back?.lastScanOffset == 8)
    }

    @Test func findingsRoundTripAndReplace() throws {
        let (store, u) = try tempStore(); defer { try? FileManager.default.removeItem(at: u) }
        let fp = SecretFingerprint(bytes: Data(repeating: 0x07, count: 32))
        let identity = SecretIdentity(fingerprint: fp, kind: .githubToken, label: "GitHub token",
                                      maskedDisplay: "ghp_••91D4", confidence: .high,
                                      firstSeen: Date(timeIntervalSince1970: 1), lastSeen: Date(timeIntervalSince1970: 2))
        let occ = SecretOccurrence(
            secretID: identity.id, fingerprint: fp, adapterID: AdapterID("claude-code"),
            storeID: StoreID("claude-transcripts"), artifactURL: URL(fileURLWithPath: "/a.jsonl"),
            fileIdentity: FileIdentity(device: 1, inode: 2, size: 3, modified: Date(timeIntervalSince1970: 3)),
            sessionID: "sess", projectPath: "/proj", recordLocator: .plainFile,
            serializedByteRange: 0..<5, feasibility: .byteLengthPreserving, discoveredAt: Date(timeIntervalSince1970: 4))

        try store.saveIdentity(identity)
        try store.saveOccurrences(path: "/a.jsonl", [occ])
        let ids = try store.loadIdentities()
        let occs = try store.loadOccurrencesByPath()
        #expect(ids[fp]?.label == "GitHub token")
        #expect(occs["/a.jsonl"]?.count == 1)
        #expect(occs["/a.jsonl"]?.first?.secretID == identity.id)

        // Re-saving the same path replaces rather than appends.
        try store.saveOccurrences(path: "/a.jsonl", [occ])
        #expect((try store.loadOccurrencesByPath())["/a.jsonl"]?.count == 1)
        try store.deleteOccurrences(path: "/a.jsonl")
        #expect((try store.loadOccurrencesByPath())["/a.jsonl"] == nil)
    }

    @Test func eventsAppendAndReadNewestFirst() throws {
        let (store, u) = try tempStore(); defer { try? FileManager.default.removeItem(at: u) }
        try store.append(AuditEvent(ts: Date(timeIntervalSince1970: 1), kind: "scan.finished",
                                    adapterID: "claude-code", storeID: nil, fingerprintPrefix: nil,
                                    artifactID: nil, message: "swept"))
        try store.append(AuditEvent(ts: Date(timeIntervalSince1970: 2), kind: "finding.new",
                                    adapterID: "claude-code", storeID: "claude-transcripts",
                                    fingerprintPrefix: "deadbeef", artifactID: "/a.jsonl", message: "found"))
        let recent = try store.recentEvents(limit: 10)
        #expect(recent.first?.kind == "finding.new")   // newest first
        #expect(recent.count == 2)
    }
}
