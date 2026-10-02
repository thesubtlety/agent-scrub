import ArgumentParser
import ClaudeCodeAdapter
import CodexAdapter
import GeminiAdapter
import VSCodeAdapter
import ClineAdapter
import AiderAdapter
import ContinueAdapter
import PiAdapter
import Foundation
import HistoryGuardCore
import SecretDetection

@main
struct HGCtl: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "hgctl",
        abstract: "Agent Scrub developer CLI. Read-only: enumerates and scans supported AI history stores.",
        subcommands: [Coverage.self, Scan.self, Redact.self, Verify.self, Policy.self, Enforce.self],
        defaultSubcommand: Coverage.self)
}

struct CommonOptions: ParsableArguments {
    @Option(name: .long, help: "Additional Claude Code data root (repeatable).")
    var root: [String] = []

    @Option(name: .long, help: "Additional Codex home (repeatable).")
    var codexRoot: [String] = []

    @Option(name: .long, help: "Additional Gemini CLI home (repeatable).")
    var geminiRoot: [String] = []

    @Option(name: .long, help: "Additional VS Code / Cursor / Windsurf editor dir (repeatable).")
    var vscodeRoot: [String] = []

    @Option(name: .long, help: "Additional Cline home (a saoudrizwan.claude-dev dir or ~/.cline) (repeatable).")
    var clineRoot: [String] = []

    @Option(name: .long, help: "Additional project root to search for Aider history (repeatable).")
    var aiderRoot: [String] = []

    @Option(name: .long, help: "Additional Continue home (~/.continue) (repeatable).")
    var continueRoot: [String] = []

    @Option(name: .long, help: "Additional Pi home (~/.pi) or session dir (repeatable).")
    var piRoot: [String] = []

    @Flag(name: .long, help: "Also scan extended residue stores (file history, debug logs, …).")
    var extended = false

    @Flag(name: .long, help: "Ignore ~/.claude, CLAUDE_CONFIG_DIR, ~/.codex and CODEX_HOME; use only --root/--codex-root.")
    var noDefaultRoots = false

    /// Every supported agent. Adapters with no installation simply contribute nothing.
    func adapters() -> [any AgentAdapter] {
        [ClaudeCodeAdapter(additionalRoots: root.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         CodexAdapter(additionalRoots: codexRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         GeminiAdapter(additionalRoots: geminiRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         VSCodeAdapter(additionalRoots: vscodeRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         ClineAdapter(additionalRoots: clineRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         AiderAdapter(additionalRoots: aiderRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         ContinueAdapter(additionalRoots: continueRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots),
         PiAdapter(additionalRoots: piRoot.map { URL(fileURLWithPath: $0) }, includeDefaultRoots: !noDefaultRoots)]
    }

    /// (adapter, installation) pairs across all agents.
    func installations() async -> [(adapter: any AgentAdapter, installation: AgentInstallation)] {
        var out: [(any AgentAdapter, AgentInstallation)] = []
        for a in adapters() { for i in await a.discoverInstallations() { out.append((a, i)) } }
        return out
    }
}

extension StoreTier {
    var label: String {
        switch self {
        case .conversation: "conversation"
        case .memory: "memory"
        case .extended: "extended"
        case .excluded: "excluded"
        }
    }
}

func rel(_ url: URL, to root: URL) -> String {
    let r = root.path.hasSuffix("/") ? root.path : root.path + "/"
    return url.path.hasPrefix(r) ? String(url.path.dropFirst(r.count)) : url.path
}

struct Coverage: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List discovered installations, stores and coverage gaps.")
    @OptionGroup var common: CommonOptions

    func run() async throws {
        let pairs = await common.installations()
        if pairs.isEmpty { print("No supported agent installation found."); return }
        for (adapter, inst) in pairs {
            print("\(adapter.displayName) \(inst.version ?? "(version unknown)")")
            print("Root: \(inst.rootURL.path)\n")
            let (stores, gaps) = try await adapter.enumerateStores(installation: inst)
            for tier in [StoreTier.conversation, .memory, .extended, .excluded] {
                let rows = stores.filter { $0.tier == tier }
                if rows.isEmpty { continue }
                print("  [\(tier.label)]")
                for s in rows {
                    let mark = s.present ? (tier == .excluded ? "–" : (tier == .extended && !common.extended ? "○" : "✓")) : "·"
                    var line = "  \(mark) \(s.displayName.padding(toLength: 44, withPad: " ", startingAt: 0))"
                    if s.present { line += s.locations.map { rel($0, to: inst.rootURL) }.joined(separator: ", ") } else { line += "(not present)" }
                    print(line)
                    if let why = s.exclusionReason, s.present { print("      \(why)") }
                }
            }
            if !gaps.isEmpty {
                print("\n  ⚠ Coverage gaps (\(gaps.count))")
                for g in gaps { print("    \(rel(URL(fileURLWithPath: g.path), to: inst.rootURL)): \(g.reason)") }
            }
            print()
        }
    }
}

struct Scan: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Read-only scan of all supported stores. Prints masked findings only.")
    @OptionGroup var common: CommonOptions

    @Flag(name: .long, help: "Emit the full report as JSON (contains no plaintext).")
    var json = false

    @Flag(name: .long, help: "List every occurrence, not just per-store counts.")
    var verbose = false

    @Option(name: .long, help: "Installation key file (default: $XDG_DATA_HOME/history-guard/installation.key).")
    var keyFile: String?

    @Option(name: .long, help: "Restrict detection to these rule ids (repeatable; development aid).")
    var rule: [String] = []

    func run() async throws {
        let keyStore = FileInstallationKeyStore(url: keyFile.map { URL(fileURLWithPath: $0) } ?? FileInstallationKeyStore.defaultLocation())
        let catalog = try RuleCatalog.bundled().filtered(ids: Set(rule))
        let scanner = SecretScanner(catalog: catalog)
        let fingerprinter = Fingerprinter(key: try keyStore.loadOrCreate())
        let pairs = await common.installations()
        if pairs.isEmpty { print("No supported agent installation found."); return }

        for (adapter, inst) in pairs {
            let engine = ScanEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter)
            let report = try await engine.scan(installation: inst, options: ScanOptions(includeExtended: common.extended))
            if json {
                let enc = JSONEncoder()
                enc.outputFormatting = [.prettyPrinted, .sortedKeys]
                enc.dateEncodingStrategy = .iso8601
                print(String(decoding: try enc.encode(report), as: UTF8.self))
                continue
            }
            printHuman(report)
            if ScanProfile.shared.enabled { print(ScanProfile.shared.report()) }
        }
    }

    func printHuman(_ r: ScanReport) {
        let policies = (try? FilePolicyStore(url: FilePolicyStore.defaultLocation()).all()) ?? [:]
        let root = r.installation.rootURL
        let dur = String(format: "%.1fs", r.finishedAt.timeIntervalSince(r.startedAt))
        let mb = String(format: "%.1f MB", Double(r.bytesExamined) / 1e6)
        print("\(r.installation.adapterID.rawValue) \(r.installation.version ?? "") · \(root.path)")
        print("Scanned \(r.artifactsScanned) artifacts, \(mb) in \(dur)\n")

        let storeName = Dictionary(uniqueKeysWithValues: r.stores.map { ($0.id, $0.displayName) })
        if r.secrets.isEmpty {
            print("No detected secrets.")
        } else {
            print("\(r.secrets.count) secret(s) in \(r.occurrences.count) local copies\n")
            for s in r.secrets {
                let occ = r.occurrences(of: s)
                let policy = policies[s.fingerprint].map { "  policy: \(describe($0.policy))" } ?? ""
                print("\(s.alias)   \(s.maskedDisplay)   [\(s.confidence.rawValue)]   \(occ.count) cop\(occ.count == 1 ? "y" : "ies")   fp:\(s.fingerprint.shortHex)\(policy)")
                let byStore = Dictionary(grouping: occ, by: \.storeID).sorted { $0.value.count > $1.value.count }
                for (sid, list) in byStore {
                    print("    \(storeName[sid] ?? sid.rawValue): \(list.count)")
                    if verbose {
                        for o in list {
                            var extra = "\(o.recordLocator) bytes \(o.serializedByteRange.lowerBound)..<\(o.serializedByteRange.upperBound) \(o.feasibility.rawValue)"
                            if let a = r.activeArtifacts[o.artifactURL] { extra += "  ACTIVE: \(a)" }
                            print("        \(rel(o.artifactURL, to: root))  \(extra)")
                        }
                    }
                }
                print()
            }
        }

        let scanned = r.stores.filter { $0.present && $0.tier != .excluded && (common.extended || $0.tier != .extended) }
        print("Coverage: \(scanned.count) stores scanned" + (r.gaps.isEmpty ? "" : ", \(r.gaps.count) gap(s)"))
        let grouped = Dictionary(grouping: r.gaps) { g -> String in
            switch g.reason {
            case .unknownStore: "unknown store"
            case .truncatedTail: "truncated final record (file may be in use)"
            case .corruptRecord: "unparseable record"
            case .oversizeArtifact: "oversize artifact"
            case .oversizeRecord: "oversize record skipped"
            case .skippedSymlink: "symlink skipped"
            case .binaryArtifact: "binary artifact"
            case .unreadable: "unreadable"
            case .unsupportedSchema: "unsupported schema"
            case .excludedByPolicy: "excluded by policy"
            case .offsetsUnreliable: "offsets unreliable"
            }
        }
        for (k, v) in grouped.sorted(by: { $0.key < $1.key }) {
            print("  \(k): \(v.count)")
            for g in v.prefix(verbose ? v.count : 5) { print("      \(rel(URL(fileURLWithPath: g.path), to: root))") }
            if !verbose, v.count > 5 { print("      … \(v.count - 5) more (use --verbose)") }
        }
        print(r.isVerifiedClean ? "\n✓ Verified clean across scanned stores." : "\n⚠ Not verified clean.")
    }
}


// MARK: - Shared helpers

func describe(_ p: RetentionPolicy) -> String {
    switch p {
    case .redactNow: "redact now"
    case .redactWhenSessionEnds: "redact when session ends"
    case let .keepUntil(d): "keep until \(d.formatted(.iso8601))"
    case .alwaysRedact: "always redact"
    case .alwaysKeep: "always keep"
    case .falsePositive: "not a secret"
    }
}

struct Toolkit {
    let common: CommonOptions
    let scanner: SecretScanner
    let fingerprinter: Fingerprinter
    let policies: FilePolicyStore

    init(common: CommonOptions, keyFile: String?) throws {
        self.common = common
        scanner = SecretScanner(catalog: try RuleCatalog.bundled())
        let keyStore = FileInstallationKeyStore(url: keyFile.map { URL(fileURLWithPath: $0) } ?? FileInstallationKeyStore.defaultLocation())
        fingerprinter = Fingerprinter(key: try keyStore.loadOrCreate())
        policies = FilePolicyStore(url: FilePolicyStore.defaultLocation())
    }

    func installations() async -> [(adapter: any AgentAdapter, installation: AgentInstallation)] { await common.installations() }
    func scanEngine(_ adapter: any AgentAdapter) -> ScanEngine { ScanEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }
    func redactionEngine(_ adapter: any AgentAdapter) -> RedactionEngine { RedactionEngine(adapter: adapter, scanner: scanner, fingerprinter: fingerprinter) }

    func secrets(matching prefix: String, in report: ScanReport) -> [SecretIdentity] {
        let p = prefix.lowercased()
        return report.secrets.filter { $0.fingerprint.hex.hasPrefix(p) }
    }
}

func printPlan(_ plan: RedactionPlan, report: ScanReport, root: URL) {
    let storeName = Dictionary(uniqueKeysWithValues: report.stores.map { ($0.id, $0.displayName) })
    let byStore = Dictionary(grouping: plan.targets, by: \.storeID)
    print("Plan: \(plan.targets.count) cop\(plan.targets.count == 1 ? "y" : "ies") to overwrite in place")
    for (sid, ts) in byStore.sorted(by: { $0.value.count > $1.value.count }) {
        print("    \(storeName[sid] ?? sid.rawValue): \(ts.count)")
        for t in ts { print("        \(rel(t.artifactURL, to: root))  \(t.locator)  \(t.range.count) bytes") }
    }
    if !plan.deferred.isEmpty {
        let occ = Dictionary(uniqueKeysWithValues: report.occurrences.map { ($0.id, $0) })
        print("Deferred: \(plan.deferred.count)")
        for (id, why) in plan.deferred {
            print("    \(occ[id].map { rel($0.artifactURL, to: root) } ?? id.uuidString): \(why)")
        }
    }
}

func printVerification(_ v: VerificationResult, root: URL) {
    if v.isVerifiedClean {
        print("✓ Verified: 0 copies remain across \(v.scannedStores.count) scanned stores.")
    } else {
        print("⚠ \(v.occurrencesRemaining.count) cop\(v.occurrencesRemaining.count == 1 ? "y" : "ies") remain; \(v.skippedStores.count) coverage gap(s) block a clean claim.")
        for o in v.occurrencesRemaining.prefix(10) { print("    \(rel(o.artifactURL, to: root))  \(o.recordLocator)") }
    }
}

// MARK: - redact

struct Redact: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Overwrite every supported copy of one secret in place, then verify. Dry-run unless --yes.")
    @OptionGroup var common: CommonOptions
    @Option(name: .long, help: "Fingerprint prefix (from `scan` output, fp:xxxxxxxx).") var fingerprint: String
    @Flag(name: .long, help: "Actually write. Without this the plan is printed and nothing changes.") var yes = false
    @Flag(name: .long, help: "Also overwrite inside artifacts that look active (a Claude Code process is running and the file changed recently).") var allowActive = false
    @Option(name: .long) var keyFile: String?

    func run() async throws {
        let kit = try Toolkit(common: common, keyFile: keyFile)
        for (adapter, inst) in await kit.installations() {
            let options = ScanOptions(includeExtended: common.extended)
            let report = try await kit.scanEngine(adapter).scan(installation: inst, options: options)
            let matches = kit.secrets(matching: fingerprint, in: report)
            guard matches.count == 1, let secret = matches.first else {
                print(matches.isEmpty ? "\(adapter.displayName) \(inst.rootURL.path): no secret with fingerprint prefix \(fingerprint)." : "Ambiguous prefix; matches \(matches.count) secrets. Use more characters.")
                continue
            }
            print("\(adapter.displayName) · \(inst.rootURL.path)")
            print("\(secret.alias)   \(secret.maskedDisplay)   fp:\(secret.fingerprint.shortHex)\n")
            let redaction = RedactionOptions(allowActiveArtifacts: allowActive, scanOptions: options)
            let engine = kit.redactionEngine(adapter)
            let plan = await engine.plan(report: report, fingerprints: [secret.fingerprint], options: redaction)
            printPlan(plan, report: report, root: inst.rootURL)
            guard yes else { print("\nDry run. Re-run with --yes to apply."); continue }
            guard !plan.targets.isEmpty else { print("\nNothing to write."); continue }

            let result = try await adapter.apply(plan: plan, verifyPreimage: engine.preimageVerifier())
            print("\nApplied \(result.appliedCount)/\(plan.targets.count).")
            for (id, why) in result.failed {
                let t = plan.targets.first { $0.id == id }
                print("    failed \(t.map { rel($0.artifactURL, to: inst.rootURL) } ?? id.uuidString): \(why)")
            }
            let verification = try await engine.verify(installation: inst, fingerprints: [secret.fingerprint], scanOptions: options)
            if let v = verification[secret.fingerprint] { printVerification(v, root: inst.rootURL) }
        }
    }
}

// MARK: - verify

struct Verify: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Fresh scan; report whether any copies of a secret remain.")
    @OptionGroup var common: CommonOptions
    @Option(name: .long) var fingerprint: String
    @Option(name: .long) var keyFile: String?

    func run() async throws {
        let kit = try Toolkit(common: common, keyFile: keyFile)
        guard let data = Data(hexString: fingerprint.lowercased()), data.count == 32 else {
            // Prefixes are resolved through a scan first.
            for (adapter, inst) in await kit.installations() {
                let report = try await kit.scanEngine(adapter).scan(installation: inst, options: ScanOptions(includeExtended: common.extended))
                let matches = kit.secrets(matching: fingerprint, in: report)
                print("\(adapter.displayName) · \(inst.rootURL.path)")
                if matches.isEmpty {
                    let blocking = report.gaps.filter(\.blocksCleanClaim)
                    print(blocking.isEmpty ? "  ✓ No copies with prefix \(fingerprint) in \(report.scannedStoreIDs.count) scanned stores."
                                           : "  ⚠ No copies found, but \(blocking.count) coverage gap(s) block a clean claim.")
                }
                for s in matches { print("  ⚠ \(s.alias): \(report.occurrences(of: s).count) cop\(report.occurrences(of: s).count == 1 ? "y" : "ies") remain") }
            }
            return
        }
        let fp = SecretFingerprint(bytes: data)
        for (adapter, inst) in await kit.installations() {
            print("\(adapter.displayName) · \(inst.rootURL.path)")
            let v = try await kit.redactionEngine(adapter).verify(installation: inst, fingerprints: [fp], scanOptions: ScanOptions(includeExtended: common.extended))
            if let r = v[fp] { printVerification(r, root: inst.rootURL) }
        }
    }
}

// MARK: - policy

struct Policy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List or set retention policies per secret fingerprint.",
                                                    subcommands: [List.self, Set.self, Remove.self], defaultSubcommand: List.self)

    struct List: AsyncParsableCommand {
        func run() async throws {
            let all = try FilePolicyStore(url: FilePolicyStore.defaultLocation()).all()
            if all.isEmpty { print("No policies."); return }
            for (fp, rec) in all.sorted(by: { $0.value.createdAt < $1.value.createdAt }) {
                print("fp:\(fp.shortHex)  \(rec.label.padding(toLength: 28, withPad: " ", startingAt: 0))  \(describe(rec.policy))   since \(rec.createdAt.formatted(.iso8601))")
            }
        }
    }

    struct Set: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Set a policy: always-redact | always-keep | not-a-secret | redact-when-session-ends | keep-until <ISO-8601>")
        @OptionGroup var common: CommonOptions
        @Option(name: .long) var fingerprint: String
        @Argument var policy: String
        @Argument var until: String?
        @Option(name: .long) var keyFile: String?

        func run() async throws {
            let kit = try Toolkit(common: common, keyFile: keyFile)
            let chosen: RetentionPolicy
            switch policy {
            case "always-redact": chosen = .alwaysRedact
            case "always-keep": chosen = .alwaysKeep
            case "not-a-secret": chosen = .falsePositive
            case "redact-when-session-ends": chosen = .redactWhenSessionEnds
            case "keep-until":
                guard let u = until, let d = try? Date(u, strategy: .iso8601) else { throw ValidationError("keep-until needs an ISO-8601 date") }
                chosen = .keepUntil(d)
            default: throw ValidationError("unknown policy \(policy)")
            }
            var found = false
            for (adapter, inst) in await kit.installations() {
                let report = try await kit.scanEngine(adapter).scan(installation: inst, options: ScanOptions(includeExtended: common.extended))
                let matches = kit.secrets(matching: fingerprint, in: report)
                guard matches.count == 1, let s = matches.first else {
                    if matches.count > 1 { print("Ambiguous prefix (\(matches.count) matches).") }
                    continue
                }
                try kit.policies.set(PolicyRecord(policy: chosen, label: s.alias), for: s.fingerprint)
                print("\(s.alias) → \(describe(chosen))")
                found = true
            }
            if !found { print("No secret with that prefix in any installation.") }
        }
    }

    struct Remove: AsyncParsableCommand {
        @Option(name: .long) var fingerprint: String
        func run() async throws {
            let store = FilePolicyStore(url: FilePolicyStore.defaultLocation())
            let all = try store.all()
            let hits = all.keys.filter { $0.hex.hasPrefix(fingerprint.lowercased()) }
            guard hits.count == 1, let fp = hits.first else { print(hits.isEmpty ? "No policy with that prefix." : "Ambiguous prefix."); return }
            try store.remove(fp)
            print("Removed policy for fp:\(fp.shortHex).")
        }
    }
}

// MARK: - enforce

struct Enforce: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Scan, then redact every copy of each secret with an always-redact policy. Dry-run unless --yes.")
    @OptionGroup var common: CommonOptions
    @Flag(name: .long) var yes = false
    @Flag(name: .long) var allowActive = false
    @Option(name: .long) var keyFile: String?

    func run() async throws {
        let kit = try Toolkit(common: common, keyFile: keyFile)
        let policies = try kit.policies.all()
        // always-redact: every copy, now. redact-when-session-ends: every copy in an inactive artifact (the
        // planner defers active ones). keep-until: once expired, treated like redact-when-session-ends.
        let enforced = Swift.Set(policies.filter { entry in
            switch entry.value.policy {
            case .alwaysRedact, .redactWhenSessionEnds, .redactNow: return true
            case let .keepUntil(until): return until < Date()
            case .alwaysKeep, .falsePositive: return false
            }
        }.keys)
        if enforced.isEmpty { print("No policies that call for redaction."); return }
        for (adapter, inst) in await kit.installations() {
            let options = ScanOptions(includeExtended: common.extended)
            let report = try await kit.scanEngine(adapter).scan(installation: inst, options: options)
            let present = enforced.intersection(report.occurrences.map(\.fingerprint))
            print("\(adapter.displayName) · \(inst.rootURL.path)")
            if present.isEmpty { print("  ✓ no copies of \(enforced.count) policy-covered secret(s)."); continue }
            let engine = kit.redactionEngine(adapter)
            let plan = await engine.plan(report: report, fingerprints: present, options: RedactionOptions(allowActiveArtifacts: allowActive, scanOptions: options))
            printPlan(plan, report: report, root: inst.rootURL)
            guard yes else { print("\nDry run. Re-run with --yes to apply."); continue }
            let result = try await adapter.apply(plan: plan, verifyPreimage: engine.preimageVerifier())
            print("\nApplied \(result.appliedCount)/\(plan.targets.count).")
            let verification = try await engine.verify(installation: inst, fingerprints: present, scanOptions: options)
            for (fp, v) in verification { print("fp:\(fp.shortHex)"); printVerification(v, root: inst.rootURL) }
        }
    }
}
