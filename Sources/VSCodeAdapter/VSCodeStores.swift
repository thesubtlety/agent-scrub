import Foundation
import HistoryGuardCore

/// What this adapter knows about VS Code (and forks: Cursor, Windsurf, VSCodium) chat storage. Everything but the
/// chat databases and session files is reported as one excluded store — we scan chat, not the whole editor dir.
enum VSCodeStores {
    static let adapterID = AdapterID("vscode-chat")
    static let schemaVersion = "1.0"

    static let globalDB = StoreID("vscode-global-db")
    static let workspaceDB = StoreID("vscode-workspace-db")
    static let chatSessions = StoreID("vscode-chat-sessions")
    static let other = StoreID("vscode-other")

    /// Editor application-support directory names that store AI chat in a `User/` subtree.
    static let editorDirNames = ["Cursor", "Code", "Code - Insiders", "Windsurf", "VSCodium"]

    /// Key/value tables inside `state.vscdb` that hold chat blobs.
    static let kvTables = ["ItemTable", "cursorDiskKV"]

    /// GLOBs on the `key` column that select chat rows (Cursor/Copilot/Windsurf/Cody), to bound scan cost. These
    /// are matched loosely on purpose — schemas drift across editor releases.
    static let chatKeyGlobs = [
        "composer*",            // Cursor composerData:/composer.composerHeaders
        "bubbleId:*",           // Cursor per-message rows
        "cascade*",             // Windsurf Cascade
        "agentData:*", "flowData:*",
        "*chatdata", "*chatData",
        "cody-local-chatHistory-v2",   // Cody
        "chat.*",               // VS Code core chat
        "*aichat*", "*ChatHistory*", "*chatSession*",
    ]
}
