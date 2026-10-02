import Foundation
import HistoryGuardCore

/// What this adapter version knows about a Cline root. Two layouts are supported: the legacy VS Code
/// extension storage (`.../globalStorage/saoudrizwan.claude-dev/` with `tasks/`, `state/`, `checkpoints/`)
/// and the newer SDK-era `~/.cline` (with `data/sessions/`). Anything unrecognised is a coverage gap.
enum ClineStores {
    static let adapterID = AdapterID("cline")
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

    // `tasks/` feeds two stores (conversations + ui-messages); `data/` feeds sessions.
    static let conversations = StoreID("conversations")
    static let uiMessages = StoreID("ui-messages")
    static let taskHistory = StoreID("task-history")
    static let sessions = StoreID("sessions")

    static let known: [Known] = [
        // Legacy globalStorage layout.
        Known("conversations", "Task conversations", .conversation, ["tasks"]),
        Known("ui-messages", "Task UI messages", .conversation, []),
        Known("task-history", "Task history", .conversation, ["state"]),
        Known("checkpoints", "Checkpoints", .extended, ["checkpoints"]),
        // SDK-era ~/.cline layout.
        Known("sessions", "SDK sessions", .conversation, ["data"]),

        Known("settings", "Settings and config", .excluded,
              ["settings.json", "config.json", "mcp.json", "mcpSettings.json", "cache"],
              excluded: "User configuration"),
    ]

    /// Files under the root that are safe to ignore without a coverage gap.
    static let ignorableRootEntries: Set<String> = [".DS_Store"]

    static func store(claiming entry: String) -> Known? {
        known.first { $0.entries.contains(entry) }
    }

    /// Owner store for a file under `tasks/`. `c[0]` is the task id, `c[1]` the filename.
    static func classifyTasksFile(relativeComponents c: [String]) -> StoreID? {
        guard c.count >= 2, c.last?.hasSuffix(".json") == true || c.last?.hasSuffix(".jsonl") == true else { return nil }
        return c.last == "ui_messages.json" ? uiMessages : conversations
    }

    /// Owner store for a file under `data/`. Only `data/sessions/<id>/*.json` is content.
    static func classifyDataFile(relativeComponents c: [String]) -> StoreID? {
        guard c.count >= 3, c[0] == "sessions",
              c.last?.hasSuffix(".json") == true || c.last?.hasSuffix(".jsonl") == true else { return nil }
        return sessions
    }
}
