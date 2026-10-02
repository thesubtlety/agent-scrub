import Foundation
import HistoryGuardCore

/// The human-facing app name for an occurrence. Most adapters are one app, but the VS Code adapter covers several
/// editors (Cursor, VS Code, Windsurf, VSCodium, …) under one adapter id, so for those we read the real editor
/// from the path — the folder right after "Application Support", the same component the adapter keys activity on.
/// Used for the Overview "By app" breakdown and the Discovered filter so a Cursor secret reads as "Cursor", not
/// the shared "vscode" adapter id.
enum AppLabel {
    static func of(_ occ: SecretOccurrence) -> String {
        // The VS Code adapter's id is "vscode-chat"; match by prefix so an id tweak can't silently stop resolving.
        guard occ.adapterID.rawValue.hasPrefix("vscode") else { return displayName(forAdapter: occ.adapterID.rawValue) }
        let comps = occ.artifactURL.pathComponents
        if let i = comps.firstIndex(of: "Application Support"), i + 1 < comps.count { return editorName(comps[i + 1]) }
        return "VS Code family"
    }

    private static func editorName(_ folder: String) -> String {
        switch folder {
        case "Code": "VS Code"
        case "Code - Insiders": "VS Code Insiders"
        default: folder   // Cursor, Windsurf, VSCodium, …
        }
    }

    private static func displayName(forAdapter id: String) -> String {
        switch id {
        case "claude-code": "Claude Code"
        case "codex": "Codex"
        case "gemini-cli": "Gemini CLI"
        case "aider": "Aider"
        case "cline": "Cline"
        case "continue": "Continue"
        case "pi": "Pi"
        default: id
        }
    }
}
