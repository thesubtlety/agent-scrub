import ClaudeCodeAdapter
import Foundation
import HistoryGuardCore
import SecretDetection
import Testing

/// A private copy of the version-A fixture tree; every test mutates its own copy.
struct Sandbox {
    let root: URL
    let adapter = ClaudeCodeAdapter()
    let scanner = SecretScanner(catalog: try! RuleCatalog.bundled())
    let fingerprinter = Fingerprinter(key: InstallationKey(data: Data(repeating: 3, count: 32)))

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("hg-redact-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: install("version-A").rootURL, to: root)
        // Copying stamps every file with "now"; age them so only files a test touches look active.
        let old = Date(timeIntervalSinceNow: -86400)
        let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        for case let u as URL in e { try FileManager.default.setAttributes([.modificationDate: old], ofItemAtPath: u.path) }
    }

    /// The fixture deliberately contains unknown-store gaps; remove them when a test needs a clean claim.
    func removeUnknownStores() throws {
        try FileManager.default.removeItem(at: root.appendingPathComponent("agent-scratch"))
        try FileManager.default.removeItem(at: root.appendingPathComponent("projects/-Users-dev-payments-api/847ab000-0000-4000-8000-000000000001/unknown-thing.txt"))
    }
    func destroy() { try? FileManager.default.removeItem(at: root) }

    var installation: AgentInstallation { AgentInstallation(adapterID: adapter.id, rootURL: root, version: nil) }
    var scan: ScanEngine { ScanEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }
    var redaction: RedactionEngine { RedactionEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }

    func report(extended: Bool = false) async throws -> ScanReport {
        try await scan.scan(installation: installation, options: ScanOptions(includeExtended: extended))
    }

    func identities() throws -> [URL: FileIdentity] {
        var out: [URL: FileIdentity] = [:]
        let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        for case let u as URL in e where (try? u.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true {
            out[u.standardizedFileURL] = try FileIdentity.read(at: u)
        }
        return out
    }

    /// Every line of every JSONL file under the root must still be structurally valid JSON.
    func assertAllJSONLParses() throws {
        let walker = JSONStringWalker(minimumLength: 1)
        let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        for case let u as URL in e where u.lastPathComponent.contains(".jsonl") && !u.path.contains("malformed") {
            try JSONLReader().forEachLine(at: u) { line in
                if line.bytes.isEmpty { return }
                #expect(throws: Never.self, "\(u.lastPathComponent) line \(line.index)") { _ = try walker.strings(in: line.bytes) }
            }
        }
    }
}

@Suite(.serialized) struct RedactionTests {
    @Test func redactsEveryCopyOfOneSecretAndNothingElse() async throws {
        let sb = try Sandbox(); defer { sb.destroy() }
        let before = try await sb.report()
        let gh = try #require(before.secrets.first { $0.kind == .githubToken })
        let ghCount = before.occurrences(of: gh).count
        #expect(ghCount == 6)
        let stripeBefore = before.occurrences.filter { o in before.secrets.first { $0.id == o.secretID }?.kind == .stripeKey }.count
        let idsBefore = try sb.identities()

        let (plan, result) = try await sb.redaction.redact(report: before, fingerprints: [gh.fingerprint])
        #expect(plan.deferred.isEmpty, "\(plan.deferred)")
        #expect(plan.targets.count == ghCount)
        #expect(result.appliedCount == ghCount, "\(result.failed)")

        // Same inode and same size everywhere: a surgical overwrite, never a rewrite.
        let idsAfter = try sb.identities()
        for (url, id) in idsBefore {
            #expect(idsAfter[url]?.inode == id.inode, "\(url.lastPathComponent)")
            #expect(idsAfter[url]?.size == id.size, "\(url.lastPathComponent)")
        }
        try sb.assertAllJSONLParses()

        let toolResults = try String(contentsOf: sb.root.appendingPathComponent("projects/-Users-dev-payments-api/847ab000-0000-4000-8000-000000000001/tool-results/bx1abc2de.txt"), encoding: .utf8)
        #expect(toolResults.contains("[REDACTED:GITHUB:"))
        #expect(!toolResults.contains(githubFixtureValue()))

        // Independent verification reaches zero for this secret. With the fixture's deliberate unknown-store
        // gaps still present the claim must stay blocked; once they are gone it is verified clean.
        let blocked = try #require(try await sb.redaction.verify(installation: sb.installation, fingerprints: [gh.fingerprint])[gh.fingerprint])
        #expect(blocked.occurrencesRemaining.isEmpty)
        #expect(!blocked.isVerifiedClean)
        #expect(blocked.skippedStores.count == 2)
        try sb.removeUnknownStores()
        let v = try #require(try await sb.redaction.verify(installation: sb.installation, fingerprints: [gh.fingerprint])[gh.fingerprint])
        #expect(v.occurrencesRemaining.isEmpty)
        #expect(v.isVerifiedClean)
        let after = try await sb.report()
        let stripeAfter = after.occurrences.filter { o in after.secrets.first { $0.id == o.secretID }?.kind == .stripeKey }.count
        #expect(stripeAfter == stripeBefore)
        // Copies in excluded stores and the unknown directory are not touched.
        let creds = try String(contentsOf: sb.root.appendingPathComponent("settings.json"), encoding: .utf8)
        #expect(creds.contains(githubFixtureValue()))
    }

    // Semantic rewrite: the plain copy and the JSON-escaped (multiline) copy are both removed, and every record
    // still parses afterwards.
    @Test func escapedAndPlainCopiesAreBothRedacted() async throws {
        let sb = try Sandbox(); defer { sb.destroy() }
        let report = try await sb.report()
        let pem = try #require(report.secrets.first { $0.kind == .privateKey })
        let (plan, result) = try await sb.redaction.redact(report: report, fingerprints: [pem.fingerprint])
        #expect(plan.targets.count == 2)
        #expect(plan.deferred.isEmpty)
        #expect(result.appliedCount == 2)
        try sb.assertAllJSONLParses()                   // the resized records are still valid JSON
        let v = try await sb.redaction.verify(installation: sb.installation, fingerprints: [pem.fingerprint])[pem.fingerprint]!
        #expect(v.occurrencesRemaining.isEmpty)         // no copy of this secret is left (the fixture's unrelated
                                                        // coverage gaps keep isVerifiedClean false, so don't assert it)
    }

    @Test func activeArtifactsAreDeferredUnlessAllowed() async throws {
        let sb = try Sandbox(); defer { sb.destroy() }
        try "{}".write(to: sb.root.appendingPathComponent("sessions/\(ProcessInfo.processInfo.processIdentifier).json"), atomically: true, encoding: .utf8)
        let transcript = sb.root.appendingPathComponent("projects/-Users-dev-payments-api/847ab000-0000-4000-8000-000000000001.jsonl")
        try FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: transcript.path)

        let report = try await sb.report()
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let plan = await sb.redaction.plan(report: report, fingerprints: [gh.fingerprint])
        let activeDeferrals = plan.deferred.values.filter { if case .artifactActive = $0 { return true } else { return false } }
        #expect(activeDeferrals.count == 3)   // the three copies inside the touched transcript
        #expect(plan.targets.count == 3)

        let forced = await sb.redaction.plan(report: report, fingerprints: [gh.fingerprint], options: RedactionOptions(allowActiveArtifacts: true))
        #expect(forced.targets.count == 6)
        #expect(forced.deferred.isEmpty)
    }

    @Test func changedBytesAreNeverOverwritten() async throws {
        let sb = try Sandbox(); defer { sb.destroy() }
        let report = try await sb.report()
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let plan = await sb.redaction.plan(report: report, fingerprints: [gh.fingerprint])
        let target = try #require(plan.targets.first { $0.storeID.rawValue == "tool-results" })

        // Someone else edits the file between planning and applying: same length, different bytes.
        let fh = try FileHandle(forUpdating: target.artifactURL)
        try fh.seek(toOffset: UInt64(target.range.lowerBound))
        let tampered = Data(repeating: UInt8(ascii: "Z"), count: target.range.count)
        try fh.write(contentsOf: tampered)
        try fh.close()

        let result = try await sb.adapter.apply(plan: RedactionPlan(targets: [target], deferred: [:]), verifyPreimage: sb.redaction.preimageVerifier())
        #expect(result.outcomes[target.id] == .preimageMismatch)
        let data = try Data(contentsOf: target.artifactURL)
        #expect(data[target.range] == tampered)
    }

    @Test func reapplyingAPlanIsIdempotent() async throws {
        let sb = try Sandbox(); defer { sb.destroy() }
        let report = try await sb.report()
        let gh = try #require(report.secrets.first { $0.kind == .githubToken })
        let plan = await sb.redaction.plan(report: report, fingerprints: [gh.fingerprint])
        let first = try await sb.adapter.apply(plan: plan, verifyPreimage: sb.redaction.preimageVerifier())
        #expect(first.appliedCount == plan.targets.count)
        let second = try await sb.adapter.apply(plan: plan, verifyPreimage: sb.redaction.preimageVerifier())
        #expect(second.outcomes.values.allSatisfy { $0 == .alreadyApplied })
    }

    @Test func replacementBytesAreAlwaysJSONSafeAndSameLength() {
        let fp = SecretFingerprint(bytes: Data(repeating: 0xAB, count: 32))
        for kind in SecretKind.allCases {
            for length in [8, 12, 20, 24, 27, 40, 80, 300] {
                let r = Replacement.bytes(length: length, kind: kind, fingerprint: fp)
                #expect(r.count == length)
                #expect(!r.contains(UInt8(ascii: "\"")) && !r.contains(UInt8(ascii: "\\")))
                #expect(r.allSatisfy { $0 >= 0x20 && $0 < 0x7F })
            }
        }
    }
}

func githubFixtureValue() -> String {
    let values = try! JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
    return values["github"]!
}
