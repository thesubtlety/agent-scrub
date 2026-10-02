import ClaudeCodeAdapter
import Foundation
import HistoryGuardCore
import SecretDetection
import Testing

func fixturesRoot() -> URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures")
}

func engine() throws -> ScanEngine {
    ScanEngine(adapter: ClaudeCodeAdapter(), scanner: SecretScanner(catalog: try RuleCatalog.bundled()),
               fingerprinter: Fingerprinter(key: InstallationKey(data: Data(repeating: 9, count: 32))))
}

func install(_ name: String) -> AgentInstallation {
    AgentInstallation(adapterID: AdapterID("claude-code"), rootURL: fixturesRoot().appendingPathComponent("Claude/\(name)"), version: nil)
}

@Suite struct ClaudeStoreEnumerationTests {
    @Test func knownStoresAreClaimedAndUnknownEntriesAreGaps() async throws {
        let adapter = ClaudeCodeAdapter()
        let (stores, gaps) = try await adapter.enumerateStores(installation: install("version-A"))
        let present = Dictionary(uniqueKeysWithValues: stores.map { ($0.id.rawValue, $0) })

        for id in ["prompt-history", "transcripts", "subagents", "tool-results", "memory", "paste-cache", "shell-snapshots",
                   "file-history", "bridge-spawn", "credentials", "session-markers", "settings", "config-backups",
                   "extensions", "internal-state", "global-config"] {
            #expect(present[id]?.present == true, "\(id) should be present")
        }
        #expect(present["debug"]?.present == false)
        #expect(present["credentials"]?.tier == .excluded)
        #expect(present["credentials"]?.capabilities.isEmpty == true)
        #expect(present["shell-snapshots"]?.tier == .conversation)
        #expect(present["file-history"]?.tier == .conversation)   // holds edited-file contents → default-scanned

        #expect(gaps.count == 1)
        #expect(gaps.first?.reason == .unknownStore)
        #expect(gaps.first?.path.hasSuffix("agent-scratch") == true)
    }

    @Test func projectsTreeIsSplitAcrossStores() async throws {
        let adapter = ClaudeCodeAdapter()
        let (stores, _) = try await adapter.enumerateStores(installation: install("version-A"))
        func names(_ id: String) async throws -> [String] {
            let s = stores.first { $0.id.rawValue == id }!
            return try await adapter.enumerateArtifacts(store: s, cursor: nil).artifacts.map(\.url.lastPathComponent).sorted()
        }
        #expect(try await names("transcripts") == ["847ab000-0000-4000-8000-000000000001.jsonl"])
        #expect(try await names("subagents") == ["agent-a1b2c3d4.jsonl", "agent-a1b2c3d4.meta.json"])
        #expect(try await names("tool-results") == ["bx1abc2de.txt"])
        #expect(try await names("memory") == ["MEMORY.md", "db.md"])

        let transcripts = stores.first { $0.id.rawValue == "transcripts" }!
        let page = try await adapter.enumerateArtifacts(store: transcripts, cursor: nil)
        #expect(page.gaps.contains { $0.path.hasSuffix("unknown-thing.txt") && $0.reason == .unknownStore })
        #expect(page.gaps.count == 1, "bridge-pointer.json and ccr-tip.json are known metadata, not gaps: \(page.gaps)")
        let t = page.artifacts[0]
        #expect(t.kind == .jsonl)
        #expect(t.sessionID == "847ab000-0000-4000-8000-000000000001")
        #expect(t.projectPath == "-Users-dev-payments-api")
    }
}

@Suite struct ClaudeScanTests {
    @Test func githubTokenFoundInEveryConversationCopyAndNowhereElse() async throws {
        let report = try await engine().scan(installation: install("version-A"))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let occ = report.occurrences(of: gh)
        let byStore = Dictionary(grouping: occ, by: { $0.storeID.rawValue }).mapValues(\.count)
        // history.jsonl pastedContents, transcript (user, assistant, quoted user), subagent, tool-results txt
        #expect(byStore == ["prompt-history": 1, "transcripts": 3, "subagents": 1, "tool-results": 1], "\(byStore)")
        // The copies in .credentials.json, settings.json, backups/ and the unknown agent-scratch/ dir must not be counted.
        #expect(!occ.contains { $0.artifactURL.path.contains("agent-scratch") || $0.artifactURL.path.contains("backups") })
        #expect(gh.maskedDisplay.hasPrefix("ghp_"))
        #expect(gh.confidence == .high)
    }

    @Test func allExpectedKindsAreFoundAndExcludedStoresAreNot() async throws {
        let report = try await engine().scan(installation: install("version-A"))
        let kinds = Set(report.secrets.map(\.kind))
        #expect(kinds.isSuperset(of: [.githubToken, .awsSecretAccessKey, .slackToken, .stripeKey, .databaseURL, .privateKey]))
        #expect(!kinds.contains(.awsAccessKeyID))   // a bare AWS access key ID is no longer flagged
        // The Anthropic OAuth token exists only in excluded stores.
        #expect(!kinds.contains(.anthropicKey))
        #expect(report.secrets.filter { $0.kind == .privateKey }.count == 1, "PEM in paste-cache and JSON-escaped PEM in transcript share one identity")
        #expect(!report.isVerifiedClean)
    }

    @Test func fileHistoryDefaultScannedAndExtendedStillOptIn() async throws {
        let e = try engine()
        let base = try await e.scan(installation: install("version-A"))
        let ext = try await e.scan(installation: install("version-A"), options: ScanOptions(includeExtended: true))
        // file-history now scanned by default (it holds edited-file contents).
        #expect(base.occurrences.filter { $0.storeID.rawValue == "file-history" }.count == 2)
        // The extended tier itself is still opt-in, and scanning it finds at least as much.
        #expect(!ScanOptions().tiers.contains(.extended))
        #expect(ScanOptions(includeExtended: true).tiers.contains(.extended))
        #expect(ext.occurrences.count >= base.occurrences.count)
    }

    @Test func locatorsAndFeasibilityAreExact() async throws {
        let report = try await engine().scan(installation: install("version-A"))
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
        let gh = try #require(values["github"])
        for o in report.occurrences where o.fingerprint == report.secrets.first(where: { $0.kind == .githubToken })!.fingerprint {
            let data = try Data(contentsOf: o.artifactURL)
            let slice = String(decoding: data[o.serializedByteRange], as: UTF8.self)
            #expect(slice == gh, "\(o.artifactURL.lastPathComponent) \(o.recordLocator): serialized range does not point at the token")
            #expect(o.feasibility == .byteLengthPreserving)
            if case let .jsonlRecord(_, _, pointer) = o.recordLocator, o.storeID.rawValue == "transcripts" {
                #expect(pointer.hasPrefix("/message/content"))
            }
        }
        // The PEM inside a JSON string has \n escapes inside the match: not patchable byte-for-byte.
        let pemOcc = report.occurrences.filter { o in report.secrets.first { $0.id == o.secretID }?.kind == .privateKey }
        let feas = Dictionary(grouping: pemOcc, by: \.storeID.rawValue).mapValues { $0.map(\.feasibility) }
        #expect(feas["transcripts"] == [.requiresSemanticRewrite])
        #expect(feas["paste-cache"] == [.byteLengthPreserving])
    }

    @Test func reportNeverContainsPlaintext() async throws {
        let report = try await engine().scan(installation: install("version-A"))
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        let json = String(decoding: try enc.encode(report), as: UTF8.self)
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
        for (k, v) in values where k != "pem" {
            #expect(!json.contains(v), "report leaks \(k)")
        }
        #expect(!json.contains("FAKEpassw0rd"))
        #expect(!json.contains("MIIFAKE"))
    }

    @Test func malformedLinesAreGapsButStillScanned() async throws {
        let report = try await engine().scan(installation: install("malformed"))
        let reasons = report.gaps.map(\.reason)
        #expect(reasons.contains(.corruptRecord(line: 1, detail: "")) == false) // detail is non-empty; check shape below
        #expect(reasons.contains { if case .corruptRecord(let l, _) = $0 { return l == 1 } else { return false } })
        #expect(reasons.contains(.truncatedTail(line: 3)))
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        #expect(report.occurrences(of: gh).count == 2)
        #expect(!report.isVerifiedClean)
    }

    @Test func activityUsesSessionMarkersAndRecency() async throws {
        // Copy the fixture, add a marker for *this* process, and touch a transcript.
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("hg-active-\(UUID().uuidString)")
        try fm.copyItem(at: install("version-A").rootURL, to: tmp)
        defer { try? fm.removeItem(at: tmp) }
        try "{}".write(to: tmp.appendingPathComponent("sessions/\(ProcessInfo.processInfo.processIdentifier).json"), atomically: true, encoding: .utf8)
        let transcript = tmp.appendingPathComponent("projects/-Users-dev-payments-api/847ab000-0000-4000-8000-000000000001.jsonl")
        try fm.setAttributes([.modificationDate: Date()], ofItemAtPath: transcript.path)

        let adapter = ClaudeCodeAdapter()
        let art = Artifact(url: transcript, storeID: StoreID("transcripts"), kind: .jsonl, identity: try FileIdentity.read(at: transcript))
        guard case .active = await adapter.activeState(artifact: art) else { Issue.record("expected active"); return }

        // Old file with only a dead-pid marker -> inactive.
        let old = tmp.appendingPathComponent("paste-cache/cbcb5ab17c9d306e.txt")
        try fm.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -86400)], ofItemAtPath: old.path)
        let oldArt = Artifact(url: old, storeID: StoreID("paste-cache"), kind: .plainText, identity: try FileIdentity.read(at: old))
        #expect(await adapter.activeState(artifact: oldArt) == .inactive)
    }

    @Test func discoveryHonoursConfigDirAndDedupes() async {
        let root = install("version-A").rootURL
        let adapter = ClaudeCodeAdapter(additionalRoots: [root, root.appendingPathComponent("../version-A")])
        let found = await adapter.discoverInstallations().filter { $0.rootURL.path == root.resolvingSymlinksInPath().path }
        #expect(found.count == 1)
        #expect(found.first?.version == "2.1.200")
    }
}
