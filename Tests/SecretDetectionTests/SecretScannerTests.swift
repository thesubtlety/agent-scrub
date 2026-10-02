import Foundation
import HistoryGuardCore
import SecretDetection
import Testing

struct PositiveCase: Decodable { let id: String; let text: String; let kind: SecretKind; let minConfidence: Confidence; let count: Int }
struct NegativeCase: Decodable { let id: String; let text: String }

/// The checksum-valid synthetic GitHub token from the fixture corpus.
func githubFixture() -> String {
    let values = try! JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
    return values["github"]!
}

func fixturesRoot() -> URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures")
}

@Suite struct SecretScannerTests {
    let scanner = SecretScanner(catalog: try! RuleCatalog.bundled())

    @Test func everyBundledRuleCompiles() throws {
        let catalog = try RuleCatalog.bundled()
        #expect(catalog.rejected.isEmpty, "rules the Swift regex engine rejected: \(catalog.rejected)")
        #expect(catalog.rules.count >= 220)
        #expect(catalog.rules.filter { $0.source == "gitleaks" }.count >= 213)   // 2 huggingface rules skipped; replaced by corrected custom rules
        #expect(!catalog.globalAllowlists.isEmpty)
    }

    // A placeholder pattern must only reject a value it DOMINATES. A real 40-char AWS secret that happens to
    // contain "EXAMPLE" was being discarded by the unanchored `(?i)example` placeholder — a bad miss.
    @Test func realSecretContainingPlaceholderWordIsStillDetected() {
        #expect(scanner.scan("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
            .contains { $0.kind == .awsSecretAccessKey })
        #expect(scanner.scan("aws_secret_access_key = abc123DEF456ghi789JKL012mno345PQR678stuv")
            .contains { $0.kind == .awsSecretAccessKey })
        // …but a value that IS just a placeholder word is still ignored.
        #expect(scanner.scan("api_key=example").isEmpty)
        #expect(scanner.scan("api_key=your_api_key").isEmpty)
    }

    // AI-provider keys are this tool's core use case. These were missed before: Hugging Face only allowed
    // letters (not digits), and Groq/OpenRouter/Replicate had no rule at all.
    @Test func detectsAIProviderKeys() {
        #expect(scanner.scan("hf_M5oForBFbyvQRZzUk1D6iNIb6zLKQbfPBi").contains { $0.kind == .vendorAPIKey })   // 34, has digits
        #expect(scanner.scan("gsk_" + String(repeating: "a", count: 52)).contains { $0.kind == .vendorAPIKey })
        #expect(scanner.scan("sk-or-v1-" + String(repeating: "0", count: 64)).contains { $0.kind == .vendorAPIKey })
        #expect(scanner.scan("r8_" + String(repeating: "A", count: 37)).contains { $0.kind == .vendorAPIKey })
        // A high-entropy secret that embeds a stopword as a substring ("master") must no longer be dropped.
        #expect(!scanner.scan("credential = Xq7masterV8Kd93JfLs02mZqWp1OrAb").isEmpty)
    }

    @Test func githubChecksumGatesClassicTokens() throws {
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
        let good = try #require(values["github"])
        var bad = good
        bad.removeLast(6); bad += "000000"
        #expect(scanner.scan("token \(good) here").contains { $0.kind == .githubToken })
        #expect(!scanner.scan("token \(bad) here").contains { $0.kind == .githubToken })
        // Not applicable to non-classic lengths: fine-grained tokens are not checksum-gated.
        #expect(Validators.githubChecksumValid("github_pat_" + String(repeating: "A", count: 71)))
    }

    @Test func gitleaksAllowlistDropsKnownExamples() {
        // gitleaks' aws-access-token allowlist excludes the documented example key regardless of context.
        #expect(!scanner.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE").contains { $0.kind == .awsAccessKeyID })
    }

    @Test func positiveCorpus() throws {
        let cases = try JSONDecoder().decode([PositiveCase].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/positive.json")))
        for c in cases {
            let hits = scanner.scan(c.text).filter { $0.kind == c.kind }
            #expect(hits.count == c.count, "\(c.id): expected \(c.count) \(c.kind) hit(s), got \(hits.map { "\($0.kind):\($0.confidence)" })")
            for h in hits {
                #expect(h.confidence >= c.minConfidence, "\(c.id): confidence \(h.confidence) < \(c.minConfidence)")
                #expect(!h.maskedDisplay.contains(h.plaintext), "\(c.id): mask leaks the value")
                // The match range must slice exactly the plaintext out of the text.
                let u = Array(c.text.utf8)
                #expect(String(decoding: u[h.range], as: UTF8.self) == h.plaintext, "\(c.id): range mismatch")
            }
        }
    }

    @Test func negativeCorpus() throws {
        let cases = try JSONDecoder().decode([NegativeCase].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/negative.json")))
        for c in cases {
            let hits = scanner.scan(c.text).filter { $0.confidence >= .medium }
            #expect(hits.isEmpty, "\(c.id): unexpected \(hits.map { "\($0.ruleID):\($0.confidence)" })")
        }
    }

    @Test func urlMatchExcludesTrailingProsePunctuation() {
        let hit = scanner.scan("see postgres://app:FAKEpassw0rd@db.payments.internal:5432/payments.").first!
        #expect(hit.plaintext.hasSuffix("/payments"))
        #expect(hit.kind == .databaseURL)
    }

    @Test func anchorWindowsFindEveryCopyOnceInNonASCIIText() {
        let gh = githubFixture()
        let filler = String(repeating: "café ünïcode 😀 filler ", count: 300)
        let text = filler + gh + " " + filler + gh + "\n" + filler + "\n" + gh
        let hits = scanner.scan(text).filter { $0.kind == .githubToken }
        #expect(hits.count == 3)
        let u = Array(text.utf8)
        for h in hits { #expect(String(decoding: u[h.range], as: UTF8.self) == gh) }
    }

    @Test func vendorRuleWinsOverGenericOnOverlap() throws {
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
        let hits = scanner.scan("GITHUB_TOKEN=\(try #require(values["github"]))")
        #expect(hits.count == 1)
        #expect(hits.first?.kind == .githubToken)
    }

    @Test func pemIdentityIgnoresWrapping() throws {
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: fixturesRoot().appendingPathComponent("Secrets/values.json")))
        let pem = try #require(values["pem"])
        let a = try #require(scanner.scan(pem).first)
        let b = try #require(scanner.scan(pem.replacingOccurrences(of: "\n", with: "\r\n")).first)
        #expect(a.canonical == b.canonical)
        #expect(a.maskedDisplay == "Private key · RSA")
    }

    @Test func masksRevealLittle() {
        let gh = githubFixture()
        let m = scanner.scan(gh).first!
        #expect(m.maskedDisplay.hasPrefix("ghp_"))
        #expect(m.maskedDisplay.hasSuffix(String(gh.suffix(4))))
        #expect(m.maskedDisplay.count < 20)
        let url = scanner.scan("postgres://app:FAKEpassw0rd@db.payments.internal:5432/payments").first!
        #expect(!url.maskedDisplay.contains("FAKEpassw0rd"))
        #expect(url.maskedDisplay.contains("db.payments.internal"))
    }

    @Test func identityAndOccurrenceNeverEncodePlaintext() throws {
        let gh = githubFixture()
        let m = scanner.scan("token \(gh) here").first!
        let fp = Fingerprinter(key: InstallationKey(data: Data(repeating: 7, count: 32))).fingerprint(namespace: m.namespace, canonical: m.canonical)
        let id = SecretIdentity(fingerprint: fp, kind: m.kind, label: m.label, maskedDisplay: m.maskedDisplay, confidence: m.confidence, firstSeen: .now, lastSeen: .now)
        let occ = SecretOccurrence(secretID: id.id, fingerprint: fp, adapterID: AdapterID("t"), storeID: StoreID("s"),
                                   artifactURL: URL(fileURLWithPath: "/x"), fileIdentity: FileIdentity(device: nil, inode: nil, size: 0, modified: .now),
                                   sessionID: nil, projectPath: nil, recordLocator: .plainFile, serializedByteRange: m.range,
                                   feasibility: .byteLengthPreserving, discoveredAt: .now)
        let json = String(decoding: try JSONEncoder().encode([AnyEncodable(id), AnyEncodable(occ)]), as: UTF8.self)
        #expect(!json.contains(gh))
        #expect(!json.contains("FAKEFAKE"))
        #expect(!"\(id) \(occ)".contains("FAKEFAKE"))
    }
}

struct AnyEncodable: Encodable {
    let value: any Encodable
    init(_ v: any Encodable) { value = v }
    func encode(to encoder: any Encoder) throws { try value.encode(to: encoder) }
}
