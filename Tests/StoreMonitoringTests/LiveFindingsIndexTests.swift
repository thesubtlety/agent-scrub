import Foundation
import Testing
import HistoryGuardCore
import SecretDetection
@testable import StoreMonitoring

@Suite struct LiveFindingsIndexTests {
    func finding(_ fp: SecretFingerprint, url: String, store: String) -> RawFinding {
        RawFinding(fingerprint: fp, kind: .genericAPIKey, label: "GitHub token", maskedDisplay: "ghp_••91D4",
                   confidence: .high, adapterID: AdapterID("claude-code"), storeID: StoreID(store),
                   artifactURL: URL(fileURLWithPath: url),
                   fileIdentity: FileIdentity(device: 1, inode: 1, size: 1, modified: Date()),
                   sessionID: nil, projectPath: nil, recordLocator: .plainFile,
                   serializedByteRange: 0..<5, feasibility: .byteLengthPreserving)
    }
    func delta(_ findings: [RawFinding]) -> ArtifactDelta {
        ArtifactDelta(findings: findings, gaps: [], bytesExamined: 0,
                      newCursor: ScanCursor(fileIdentity: FileIdentity(device: 1, inode: 1, size: 1, modified: Date()),
                                            lastScanOffset: 1))
    }

    // Same fingerprint in two locations → one identity, two occurrences.
    @Test func sameSecretTwoLocationsOneIdentity() {
        let fp = SecretFingerprint(bytes: Data(repeating: 0xAB, count: 32))
        var index = LiveFindingsIndex()
        index.applyFull(artifact: URL(fileURLWithPath: "/a.jsonl"),
                        delta: delta([finding(fp, url: "/a.jsonl", store: "claude-transcripts")]), now: Date())
        index.applyFull(artifact: URL(fileURLWithPath: "/b.jsonl"),
                        delta: delta([finding(fp, url: "/b.jsonl", store: "codex-rollout")]), now: Date())
        #expect(index.secrets().count == 1)
        #expect(index.occurrences().count == 2)
    }

    @Test func removeDropsOccurrencesAndIdentity() {
        let fp = SecretFingerprint(bytes: Data(repeating: 0x01, count: 32))
        var index = LiveFindingsIndex()
        let url = URL(fileURLWithPath: "/a.jsonl")
        index.applyFull(artifact: url, delta: delta([finding(fp, url: "/a.jsonl", store: "s")]), now: Date())
        index.remove(artifact: url)
        #expect(index.secrets().isEmpty)
        #expect(index.occurrences().isEmpty)
    }

    // removeFingerprints drops those occurrences everywhere and reports the affected artifacts.
    @Test func removeFingerprintsDropsAcrossArtifacts() {
        let keep = SecretFingerprint(bytes: Data(repeating: 0x11, count: 32))
        let drop = SecretFingerprint(bytes: Data(repeating: 0x22, count: 32))
        var index = LiveFindingsIndex()
        index.applyFull(artifact: URL(fileURLWithPath: "/a.jsonl"),
                        delta: delta([finding(keep, url: "/a.jsonl", store: "s"), finding(drop, url: "/a.jsonl", store: "s")]), now: Date())
        index.applyFull(artifact: URL(fileURLWithPath: "/b.jsonl"),
                        delta: delta([finding(drop, url: "/b.jsonl", store: "s")]), now: Date())
        let affected = index.removeFingerprints([drop])
        #expect(affected == [URL(fileURLWithPath: "/a.jsonl"), URL(fileURLWithPath: "/b.jsonl")])
        #expect(index.occurrences().count == 1)
        #expect(index.occurrences().allSatisfy { $0.fingerprint == keep })
        #expect(index.secrets().map(\.fingerprint) == [keep])
    }

    @Test func deltaAppendKeepsPriorOccurrences() {
        let fp = SecretFingerprint(bytes: Data(repeating: 0x02, count: 32))
        var index = LiveFindingsIndex()
        let url = URL(fileURLWithPath: "/a.jsonl")
        index.applyFull(artifact: url, delta: delta([finding(fp, url: "/a.jsonl", store: "s")]), now: Date())
        index.applyDeltaAppend(artifact: url, delta: delta([finding(fp, url: "/a.jsonl", store: "s")]), now: Date())
        #expect(index.occurrences().count == 2)   // prefix retained + appended
    }
}
