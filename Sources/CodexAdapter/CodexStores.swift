import Foundation
import HistoryGuardCore

/// What this adapter version knows about a Codex home (`~/.codex` or `$CODEX_HOME`). Derived from codex-rs
/// sources: message-history (history.jsonl), rollout (sessions/, archived_sessions/, session_index.jsonl,
/// thread-writer-locks/) and state (state_5.sqlite, thread_history_1.sqlite, logs_2.sqlite, …).
enum CodexStores {
    static let adapterID = AdapterID("codex")
    static let schemaVersion = "codex-rs 2026-09"

    static let promptHistory = StoreID("prompt-history")
    static let rollouts = StoreID("rollouts")
    static let archivedRollouts = StoreID("archived-rollouts")
    static let sessionIndex = StoreID("session-index")
    static let stateDB = StoreID("state-db")
    static let threadHistoryDB = StoreID("thread-history-db")
    static let logsDB = StoreID("logs-db")
    static let memoriesDB = StoreID("memories-db")
    static let otherDB = StoreID("other-db")

    struct Known {
        let id: StoreID
        let name: String
        let tier: StoreTier
        /// Exact root entry names, or glob-ish prefixes ending in "*".
        let entries: [String]
        let exclusionReason: String?
        init(_ id: StoreID, _ name: String, _ tier: StoreTier, _ entries: [String], excluded: String? = nil) {
            self.id = id; self.name = name; self.tier = tier; self.entries = entries; self.exclusionReason = excluded
        }
    }

    static let known: [Known] = [
        Known(promptHistory, "Prompt history", .conversation, ["history.jsonl"]),
        Known(rollouts, "Session rollouts", .conversation, ["sessions"]),
        Known(archivedRollouts, "Archived rollouts", .conversation, ["archived_sessions"]),
        Known(sessionIndex, "Session index (thread names)", .conversation, ["session_index.jsonl"]),
        Known(stateDB, "State database (thread titles, previews, attachments)", .conversation, ["state_*.sqlite"]),
        Known(threadHistoryDB, "Thread history database (materialized items)", .conversation, ["thread_history_*.sqlite"]),
        Known(memoriesDB, "Memories database", .memory, ["memories_*.sqlite"]),
        Known(logsDB, "Diagnostic log database", .extended, ["logs_*.sqlite"]),
        Known(otherDB, "Other Codex databases", .extended, ["goals_*.sqlite", "queue_*.sqlite"]),
        Known(StoreID("text-logs"), "Text logs", .extended, ["log"]),
        Known(StoreID("memories"), "Memory files", .memory, ["memories"]),

        Known(StoreID("credentials"), "Authentication (auth.json)", .excluded, ["auth.json"],
              excluded: "Login tokens Codex needs to run"),
        Known(StoreID("settings"), "Configuration", .excluded, ["config.toml", "config.json", "AGENTS.md", "instructions.md", "version.json", "models_cache.json", "notify.json"],
              excluded: "User configuration"),
        Known(StoreID("writer-locks"), "Thread writer locks", .excluded, ["thread-writer-locks"],
              excluded: "Lock files; used for activity detection only"),
        Known(StoreID("extensions"), "Skills, prompts, plugins, rules", .excluded, ["skills", "prompts", "plugins", "rules", "hooks"],
              excluded: "User-installed code and rules"),
        Known(StoreID("internal-state"), "Internal state and caches", .excluded, ["cache", "tmp", ".codex-global-state.json", "shell_snapshots", "bin", "sandbox", "cloud"],
              excluded: "Non-content bookkeeping"),
    ]

    static let ignorableRootEntries: Set<String> = [".DS_Store"]

    /// SQLite sidecars belong to their database and are covered by reading through the SQLite API.
    static func isSQLiteSidecar(_ name: String) -> Bool {
        name.hasSuffix(".sqlite-wal") || name.hasSuffix(".sqlite-shm") || name.hasSuffix(".sqlite-journal")
    }

    static func store(claiming entry: String) -> Known? {
        let base = isSQLiteSidecar(entry) ? String(entry.prefix(while: { $0 != "-" })).replacingOccurrences(of: "-", with: "") : entry
        for k in known {
            for pattern in k.entries {
                if pattern.hasSuffix("*"), base.hasPrefix(pattern.dropLast()), base.hasSuffix(".sqlite") { return k }
                if pattern == base { return k }
                if pattern.hasSuffix("*.sqlite") {
                    let prefix = pattern.dropLast("*.sqlite".count)
                    if base.hasPrefix(prefix), base.hasSuffix(".sqlite") { return k }
                }
            }
        }
        return nil
    }

    /// Columns known to mirror user-visible content, per database family. Anything else is scanned generically
    /// but flagged as an unknown schema so redaction stays disabled for it.
    struct TableSpec: Sendable { let table: String; let columns: [String]; let json: [String] }
    static let knownSchemas: [StoreID: [TableSpec]] = [
        stateDB: [
            TableSpec(table: "threads", columns: ["title", "first_user_message", "preview", "name", "git_origin_url"], json: []),
            TableSpec(table: "thread_attachments", columns: [], json: ["payload"]),
            TableSpec(table: "thread_artifacts", columns: [], json: ["payload"]),
        ],
        threadHistoryDB: [
            TableSpec(table: "thread_items", columns: [], json: ["item_json"]),
            TableSpec(table: "thread_realtime_items", columns: [], json: ["item_json"]),
            TableSpec(table: "thread_turns", columns: [], json: ["error_json"]),
        ],
        logsDB: [
            TableSpec(table: "logs", columns: ["feedback_log_body", "message"], json: []),
        ],
    ]
}
