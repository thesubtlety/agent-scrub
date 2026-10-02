import Foundation
import HistoryGuardCore

/// What this adapter version knows about the layout under a Claude Code root. Anything at the root that is
/// not claimed here is reported as an `unknownStore` coverage gap, never silently ignored.
enum ClaudeStores {
    static let adapterID = AdapterID("claude-code")
    static let schemaVersion = "2.2"

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

    // `projects` is shared by several stores; see ClaudeCodeAdapter.classifyProjectsFile.
    static let promptHistory = StoreID("prompt-history")
    static let transcripts = StoreID("transcripts")
    static let subagents = StoreID("subagents")
    static let toolResults = StoreID("tool-results")
    static let memory = StoreID("memory")
    static let projectMetadata = StoreID("project-metadata")

    static let known: [Known] = [
        Known("prompt-history", "Prompt history", .conversation, ["history.jsonl"]),
        Known("transcripts", "Session transcripts", .conversation, ["projects"]),
        Known("subagents", "Subagent transcripts", .conversation, []),
        Known("tool-results", "Spilled tool results", .conversation, []),
        Known("memory", "Persistent memory", .memory, ["agent-memory"]),
        Known("paste-cache", "Paste cache", .conversation, ["paste-cache"]),
        Known("shell-snapshots", "Shell snapshots", .conversation, ["shell-snapshots"]),

        // Pre/post-edit snapshots of file contents the agent touched — a real secret-leak surface, scanned by default.
        Known("file-history", "File history snapshots", .conversation, ["file-history"]),
        Known("debug", "Debug logs", .extended, ["debug"]),
        Known("plans", "Plans", .extended, ["plans"]),
        Known("feedback", "Feedback drafts and bundles", .extended, ["feedback", "feedback-bundles"]),
        Known("uploads", "Uploads", .extended, ["uploads"]),
        Known("downloads", "Downloads", .extended, ["downloads"]),
        Known("bridge-spawn", "Bridge session prompts", .extended, ["bridge-spawn"]),
        Known("todos", "Todo lists", .extended, ["todos"]),

        Known("credentials", "OAuth credentials", .excluded, [".credentials.json"],
              excluded: "Authentication material Claude Code needs to run"),
        Known("session-markers", "Running-session markers and keys", .excluded, ["sessions"],
              excluded: "Process markers and per-session keys; used for activity detection only"),
        Known("settings", "Settings", .excluded,
              ["settings.json", "settings.local.json", "CLAUDE.md", "keybindings.json"],
              excluded: "User configuration"),
        Known("config-backups", "Backups of ~/.claude.json", .excluded, ["backups"],
              excluded: "Copies of the global config file, which is excluded"),
        Known("extensions", "Plugins, skills, hooks, agents", .excluded,
              ["plugins", "skills", "hooks", "commands", "agents", "ide"],
              excluded: "User-installed code and rules"),
        Known("project-metadata", "Session pointers and bookkeeping", .excluded, [],
              excluded: "bridge-pointer.json and ccr-tip.json under projects/ hold pids and event ids, not content"),
        Known("internal-state", "Internal state and caches", .excluded,
              ["state", "cache", "session-env", "statsig", "telemetry", ".last-cleanup", ".last-update-result.json"],
              excluded: "Non-content bookkeeping"),
    ]

    /// Files under the root that are safe to ignore without a coverage gap.
    static let ignorableRootEntries: Set<String> = [".DS_Store"]

    static func store(claiming entry: String) -> Known? {
        if let exact = known.first(where: { $0.entries.contains(entry) }) { return exact }
        if entry.hasPrefix("settings.json.bak") { return known.first { $0.id == StoreID("settings") } }
        return nil
    }
}
