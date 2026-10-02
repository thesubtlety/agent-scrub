import Foundation
import HistoryGuardCore

/// What this adapter version knows about the layout under a Gemini CLI root (`~/.gemini`). Anything at the
/// root that is not claimed here is reported as an `unknownStore` coverage gap, never silently ignored.
enum GeminiStores {
    static let adapterID = AdapterID("gemini-cli")
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

    // The `tmp/<project_hash>/` tree feeds three stores; `chats` claims `tmp` and classifyTmpFile splits it.
    static let chats = StoreID("chats")
    static let logs = StoreID("logs")
    static let checkpoints = StoreID("checkpoints")

    static let known: [Known] = [
        Known("chats", "Chat transcripts", .conversation, ["tmp"]),
        Known("logs", "Activity logs", .conversation, []),
        Known("checkpoints", "Saved checkpoints", .conversation, []),
        Known("context", "User context (GEMINI.md)", .memory, ["GEMINI.md"]),

        Known("settings", "Settings", .excluded, ["settings.json"], excluded: "User configuration"),
        Known("credentials", "OAuth credentials and account", .excluded,
              ["oauth_creds.json", "google_accounts.json", "access_tokens.json", "installation_id", "user_id"],
              excluded: "Authentication material Gemini CLI needs to run"),
        Known("extensions", "Installed extensions, commands and MCP config", .excluded,
              ["extensions", "commands", "mcp"],
              excluded: "User-installed code and configuration"),
    ]

    /// Files under the root that are safe to ignore without a coverage gap.
    static let ignorableRootEntries: Set<String> = [".DS_Store"]

    static func store(claiming entry: String) -> Known? {
        known.first { $0.entries.contains(entry) }
    }

    /// Which store a file under `tmp/` belongs to. `c[0]` is the project hash. nil for anything unrecognised.
    static func classifyTmpFile(relativeComponents c: [String]) -> StoreID? {
        guard c.count >= 2 else { return nil }
        if c.count >= 3, c[1] == "chats", c[2].hasSuffix(".jsonl") { return chats }
        if c.count == 2, c[1] == "logs.json" { return logs }
        if c.count >= 3, c[1] == "checkpoints" { return checkpoints }
        return nil
    }
}
