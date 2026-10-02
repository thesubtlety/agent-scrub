import Foundation
import HistoryGuardCore

/// What this adapter version knows about the layout under a Pi coding-agent root (`~/.pi`). Session transcripts
/// live under `agent/sessions/--<cwd>--/<timestamp>_<id>.jsonl`. Anything at the root that is not claimed here
/// is reported as an `unknownStore` coverage gap, never silently ignored.
enum PiStores {
    static let adapterID = AdapterID("pi")
    static let schemaVersion = "1.0"

    struct Known {
        let id: StoreID
        let name: String
        let tier: StoreTier
        /// Top-level entry names under the root that this store claims.
        let entries: [String]
        let exclusionReason: String?

        init(_ id: String, _ name: String, _ tier: StoreTier, _ entries: [String], excluded: String? = nil) {
            self.id = StoreID(id)
            self.name = name
            self.tier = tier
            self.entries = entries
            self.exclusionReason = excluded
        }
    }

    static let sessions = StoreID("sessions")

    static let known: [Known] = [
        // `agent/` holds `sessions/<project>/*.jsonl`; the whole subtree is walked for transcripts.
        Known("sessions", "Agent sessions", .conversation, ["agent"]),

        Known("config", "Config and settings", .excluded,
              ["config.json", "config.yaml", "config.yml", "settings.json", "config", "settings"],
              excluded: "User configuration"),
        Known("credentials", "Credentials and auth", .excluded,
              ["auth.json", "credentials.json", "credentials", "token", "tokens.json", ".credentials"],
              excluded: "Authentication material Pi needs to run"),
    ]

    /// Files under the root that are safe to ignore without a coverage gap.
    static let ignorableRootEntries: Set<String> = [".DS_Store"]

    static func store(claiming entry: String) -> Known? {
        known.first { $0.entries.contains(entry) }
    }
}
