import Foundation
import HistoryGuardCore

/// What this adapter version knows about the layout under a Continue root (`~/.continue`). Anything at the
/// root that is not claimed here is reported as an `unknownStore` coverage gap, never silently ignored.
enum ContinueStores {
    static let adapterID = AdapterID("continue")
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
    static let devData = StoreID("dev-data")

    static let known: [Known] = [
        Known("sessions", "Chat sessions", .conversation, ["sessions"]),
        Known("dev-data", "Development data logs", .conversation, ["dev_data"]),

        Known("index", "Embeddings index", .excluded, ["index"],
              excluded: "LanceDB/SQLite embeddings, not transcripts"),
        Known("config", "Configuration", .excluded,
              ["config.yaml", "config.json", "config.ts", "config.ts.backup", ".continuerc", ".continuerc.json",
               "config.yaml.backup", "assistants", "rules", "prompts", "models"],
              excluded: "User configuration, rules and models"),
    ]

    /// Files under the root that are safe to ignore without a coverage gap.
    static let ignorableRootEntries: Set<String> = [".DS_Store", ".continueignore"]

    static func store(claiming entry: String) -> Known? {
        known.first { $0.entries.contains(entry) }
    }
}
