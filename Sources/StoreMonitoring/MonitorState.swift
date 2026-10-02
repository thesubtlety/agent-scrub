import Foundation
import HistoryGuardCore

/// An immutable snapshot the monitor publishes whenever its state changes. Carries no secret plaintext
/// beyond the masked displays already in `SecretIdentity`.
public struct MonitorState: Sendable, Equatable {
    public enum Status: Sendable, Equatable { case green, yellow, red, gray }

    public struct StoreState: Sendable, Equatable {
        public let adapterID: AdapterID
        public let storeID: StoreID
        public let displayName: String
        public let present: Bool
        public let gapCount: Int
        public init(adapterID: AdapterID, storeID: StoreID, displayName: String, present: Bool, gapCount: Int) {
            self.adapterID = adapterID; self.storeID = storeID; self.displayName = displayName
            self.present = present; self.gapCount = gapCount
        }
    }

    public let status: Status
    public let secrets: [SecretIdentity]
    public let occurrences: [SecretOccurrence]
    public let gaps: [CoverageGap]
    public let stores: [StoreState]
    public let lastVerified: Date?
    public let scanning: Bool
    /// Paths of artifacts currently in an active session (recently written while an agent runs).
    public let activeArtifacts: Set<String>
    /// Lifetime totals persisted across launches.
    public let lifetimeCopiesRedacted: Int
    public let lifetimeSecretsRedacted: Int

    public static let empty = MonitorState(status: .gray, secrets: [], occurrences: [], gaps: [],
                                           stores: [], lastVerified: nil, scanning: false)
    public init(status: Status, secrets: [SecretIdentity], occurrences: [SecretOccurrence],
                gaps: [CoverageGap], stores: [StoreState], lastVerified: Date?, scanning: Bool,
                activeArtifacts: Set<String> = [], lifetimeCopiesRedacted: Int = 0, lifetimeSecretsRedacted: Int = 0) {
        self.status = status; self.secrets = secrets; self.occurrences = occurrences; self.gaps = gaps
        self.stores = stores; self.lastVerified = lastVerified; self.scanning = scanning
        self.activeArtifacts = activeArtifacts
        self.lifetimeCopiesRedacted = lifetimeCopiesRedacted
        self.lifetimeSecretsRedacted = lifetimeSecretsRedacted
    }

    /// Whether a secret has at least one copy in an active session (shown as a "Live" badge).
    public func hasLiveCopy(_ fingerprint: SecretFingerprint) -> Bool {
        occurrences.contains { $0.fingerprint == fingerprint && activeArtifacts.contains($0.artifactURL.path) }
    }
    public func isLive(_ occurrence: SecretOccurrence) -> Bool {
        activeArtifacts.contains(occurrence.artifactURL.path)
    }
}

public extension MonitorState {
    /// "Clean" is a coverage assertion, never a bare count: true only when a reconcile has completed,
    /// nothing was found, no gap blocks a clean claim, and no monitored store is inaccessible.
    var isCoverageClean: Bool {
        lastVerified != nil && occurrences.isEmpty && !gaps.contains(where: \.blocksCleanClaim) && status != .red
    }

    /// The headline line for the Overview and the menu bar popover.
    var headline: String {
        if !occurrences.isEmpty { return "\(secrets.count) secret(s) in \(occurrences.count) local copies" }
        if isCoverageClean { return "0 detected secrets in supported AI memory" }
        if lastVerified == nil { return "Scanning supported AI memory…" }
        return "Coverage incomplete — not verified clean"
    }
}
