import Foundation
import HistoryGuardCore

/// What this adapter version knows about Aider's history files, which live INSIDE each user repo (not a central
/// app-data dir). An installation root is a repo directory that contains one of the `.aider.*` history files.
/// Any unrecognised `.aider.*` entry in that dir is reported as an `unknownStore` coverage gap, never silently
/// ignored. Non-`.aider.*` files are the user's own project and are not our concern.
enum AiderStores {
    static let adapterID = AdapterID("aider")
    static let schemaVersion = "1.0"

    struct Known {
        let id: StoreID
        let name: String
        let tier: StoreTier
        /// File names (within a repo dir) this store claims.
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

    static let chatHistory = StoreID("chat-history")
    static let inputHistory = StoreID("input-history")
    static let llmHistory = StoreID("llm-history")

    static let known: [Known] = [
        Known("chat-history", "Chat transcript", .conversation, [".aider.chat.history.md"]),
        Known("input-history", "Prompt input history", .conversation, [".aider.input.history"]),
        Known("llm-history", "Raw LLM requests/responses", .conversation, [".aider.llm.history"]),

        Known("tags-cache", "Repo-map tags cache", .excluded,
              [".aider.tags.cache.v3", ".aider.tags.cache.v4"],
              excluded: "Repo-map cache, not conversation content"),
    ]

    /// The files whose presence marks a directory as an Aider installation.
    static let markerFiles: Set<String> = [".aider.input.history", ".aider.chat.history.md"]

    /// Directory names never descended into during discovery (heavy/system/vendored trees, and the TCC-protected
    /// user folders — Desktop/Documents/Downloads/Photos etc. — so discovery doesn't trigger privacy prompts).
    /// Repos kept inside those still work if the user adds them explicitly (--aider-root / additionalRoots).
    static let denylistedDirNames: Set<String> = [
        "Library", "node_modules", "Pods", ".venv", "venv", ".tox", "build", "dist", "target",
        "DerivedData", ".Trash", ".cache", "Applications", ".npm", ".cargo", ".rustup", ".gradle",
        ".m2", "__pycache__", ".next", ".turbo", ".git", ".hg", ".svn",
        "Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Public", "Mobile Documents",
    ]

    static func store(claiming entry: String) -> Known? {
        known.first { $0.entries.contains(entry) }
    }
}
