import Foundation
import SwiftUI
import HistoryGuardCore
import StoreMonitoring
import HistoryGuardDB

/// A single-dimension filter the Overview can hand to the Discovered Secrets list.
enum SecretFilter: Equatable, Sendable {
    case kind(SecretKind)
    case app(String)       // AppLabel (e.g. "Cursor", "Codex"), not the shared adapter id
    case project(String)
    case secret(SecretFingerprint)   // focus a single secret (e.g. from the new-secret menu-bar note)
}

/// Bridges the monitor's async state stream to SwiftUI, and owns the retention policies (triage decisions)
/// that reshape the discovered-secrets list. Never shares the StateStore across isolation boundaries.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var state: MonitorState = .empty
    @Published private(set) var events: [AuditEvent] = []
    @Published private(set) var policies: [SecretFingerprint: PolicyRecord] = [:]
    /// A secret fully redacted this session, kept so the list can show a green confirmation — with its original
    /// context (where, how many) and new value — instead of the entry just vanishing. Cleared on relaunch.
    struct RedactedRecord: Identifiable {
        let identity: SecretIdentity
        let copies: Int
        let locations: [String]
        var id: SecretFingerprint { identity.fingerprint }
    }
    @Published private(set) var recentlyRedacted: [SecretFingerprint: RedactedRecord] = [:]
    /// One-shot request from Overview to open Discovered Secrets filtered to a dimension. Consumed by the view.
    @Published var navigateTo: SecretFilter?
    /// Folders the user excluded from scanning.
    @Published private(set) var exclusions: [String] = UserDefaults.standard.stringArray(forKey: "excludedFolders") ?? []

    private let service: MonitorService
    private let policyStore: FilePolicyStore

    init(service: MonitorService, policyStore: FilePolicyStore) {
        self.service = service
        self.policyStore = policyStore
        self.policies = (try? policyStore.all()) ?? [:]
        Task { [weak self] in
            guard let self else { return }
            await service.setExclusions(Set(self.exclusions))   // apply before the first scan
            await service.start()
            await service.setAutoRedact(self.autoRedactSet())   // enforce any persisted "always redact" policies
            for await snapshot in service.states {
                self.state = snapshot
                // Refresh the audit log only when a scan isn't churning — no need to re-query every tick.
                if !snapshot.scanning {
                    self.events = await service.recentEvents(limit: 200)
                    self.notifyOfNewSecrets(snapshot)
                }
            }
        }
    }

    func scanNow() { Task { await service.reconcileAll() } }

    /// True when a copy of the secret sits inside a binary record we can't fully parse (e.g. Cursor's msgpack
    /// blobs). Those aren't auto-redacted; the UI offers a deliberate per-item "force-redact" for them.
    func hasBinaryCopies(_ secret: SecretIdentity) -> Bool {
        state.occurrences.contains { $0.fingerprint == secret.fingerprint && $0.feasibility == .offsetsUnreliable }
    }

    /// Overwrite every supported copy of the secret in place and re-verify. Destructive.
    /// `allowActive` also rewrites copies in a live session (safe for append-only transcripts).
    /// `allowBinaryForce` also overwrites the exact bytes of a copy inside a binary record we can't re-parse.
    func redact(_ secret: SecretIdentity, allowActive: Bool = false, allowBinaryForce: Bool = false) async -> RedactionSummary {
        // Capture where the secret lived before it's rewritten, so the confirmation keeps its context.
        let before = state.occurrences.filter { $0.fingerprint == secret.fingerprint }
        let locations = Array(Set(before.map {
            $0.projectPath ?? $0.artifactURL.deletingLastPathComponent().lastPathComponent
        })).sorted()
        let summary = await service.redact(fingerprint: secret.fingerprint, allowActive: allowActive, allowBinaryForce: allowBinaryForce)
        // Fully cleared → remember it so the UI can confirm what it became, until the next launch.
        if summary.applied >= 1 && summary.remaining == 0 {
            recentlyRedacted[secret.fingerprint] = RedactedRecord(identity: secret, copies: summary.applied, locations: locations)
        }
        return summary
    }

    /// A short, masked one-line context around a copy, read live through the owning adapter (so a SQLite cell is
    /// read from the cell, not the database file). Nothing is stored.
    func contextExcerpt(for occ: SecretOccurrence, context: Int = 48) async -> String? {
        guard let (bytes, start) = await service.recordBytes(for: occ, before: context, after: context) else { return nil }
        return Excerpt.format(bytes: bytes, recordRange: occ.serializedByteRange, start: start)
    }

    /// The actual secret value for an explicit "Reveal", read live through the owning adapter. Never stored.
    func revealedValue(for occ: SecretOccurrence) async -> String? {
        guard let (bytes, _) = await service.recordBytes(for: occ, before: 0, after: 0),
              bytes.count == occ.serializedByteRange.count else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// The marker a redaction wrote in place of this secret (e.g. "[REDACTED:AWS:1EA4]").
    func redactedMarker(for secret: SecretIdentity) -> String {
        Replacement.marker(kind: secret.kind, fingerprint: secret.fingerprint)
    }

    func policy(for fingerprint: SecretFingerprint) -> RetentionPolicy? { policies[fingerprint]?.policy }

    /// Set (or clear, when `policy` is nil) the retention decision for a secret. Persists immediately.
    func setPolicy(_ policy: RetentionPolicy?, for secret: SecretIdentity) {
        if let policy {
            let record = PolicyRecord(policy: policy, label: secret.label)
            try? policyStore.set(record, for: secret.fingerprint)
            policies[secret.fingerprint] = record
        } else {
            try? policyStore.remove(secret.fingerprint)
            policies[secret.fingerprint] = nil
        }
        let fps = autoRedactSet()
        Task { await service.setAutoRedact(fps) }
    }

    private func autoRedactSet() -> Set<SecretFingerprint> {
        Set(policies.filter { $0.value.policy == .alwaysRedact }.map(\.key))
    }

    func addExclusion(_ path: String) {
        guard !exclusions.contains(path) else { return }
        exclusions = (exclusions + [path]).sorted()
        persistExclusions()
    }
    func removeExclusion(_ path: String) {
        exclusions.removeAll { $0 == path }
        persistExclusions()
    }
    private func persistExclusions() {
        UserDefaults.standard.set(exclusions, forKey: "excludedFolders")
        let set = Set(exclusions)
        Task { await service.setExclusions(set); await service.reconcileAll() }
    }

    /// Called on the main actor when new, un-triaged secrets appear after launch. Set by the app delegate to drop
    /// a self-dismissing note from the menu bar. Hands over the first new secret and the total new count.
    var onNewSecrets: ((SecretIdentity, Int) -> Void)?

    /// Open the Discovered list focused on one secret (used by the menu-bar note's "Review" action).
    func focus(_ secret: SecretIdentity) { navigateTo = .secret(secret.fingerprint) }
    private var knownFingerprints: Set<SecretFingerprint> = []
    private var seededKnown = false

    /// Notify once for secrets that appear after the initial load and have no decision yet (always-redact ones
    /// are handled silently by enforcement). The first settled snapshot only seeds the baseline.
    private func notifyOfNewSecrets(_ snapshot: MonitorState) {
        let current = Set(snapshot.secrets.map(\.fingerprint))
        defer { knownFingerprints = current }
        guard seededKnown else { seededKnown = true; return }
        let fresh = snapshot.secrets.filter { !knownFingerprints.contains($0.fingerprint) && policies[$0.fingerprint] == nil }
        guard let first = fresh.first else { return }
        onNewSecrets?(first, fresh.count)   // the in-app menu-bar note (doesn't need notification permission)
        Notifier.post(title: fresh.count == 1 ? "New secret found" : "\(fresh.count) new secrets found",
                      body: fresh.count == 1 ? "\(first.label) — open Agent Scrub to review"
                                             : "Including \(first.label). Open to review.")
    }
}
