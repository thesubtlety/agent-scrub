import Foundation

enum TempTree {
    /// Creates a throwaway Claude root containing one transcript at
    /// projects/<slug>/<session>.jsonl holding `line` plus a trailing newline.
    static func claudeRootWithTranscript(line: String) throws -> URL {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("hg-claude-\(UUID().uuidString)")
        let dir = root.appendingPathComponent("projects/-Users-dev-app")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("00000000-0000-4000-8000-000000000001.jsonl")
        try Data((line + "\n").utf8).write(to: file)
        return root
    }
}
