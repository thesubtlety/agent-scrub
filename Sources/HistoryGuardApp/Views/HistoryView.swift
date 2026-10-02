import SwiftUI
import HistoryGuardDB

struct HistoryView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        List(Array(model.events.enumerated()), id: \.offset) { _, e in
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Image(systemName: icon(e.kind)).foregroundStyle(tint(e.kind))
                    Text(e.message).bold()
                }
                Text(subline(e))
                    .font(.caption2).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)   // wrap long paths instead of truncating
            }
            .padding(.vertical, 1)
        }
        .overlay { if model.events.isEmpty { ContentUnavailableView("No activity yet", systemImage: "list.bullet.rectangle") } }
        .navigationTitle("Audit log")
    }

    /// "date, time: type location  full path" — e.g. "Oct 2, 2026, 3:45:12 PM: transcripts · claude-code  /Users/…/x.jsonl"
    private func subline(_ e: AuditEvent) -> String {
        let d = e.ts.formatted(date: .abbreviated, time: .omitted)
        let t = e.ts.formatted(date: .omitted, time: .standard)
        var loc: [String] = []
        if let s = e.storeID { loc.append(s) }
        if let a = e.adapterID { loc.append(a) }
        let location = loc.joined(separator: " · ")
        let path = e.artifactID ?? ""
        let tail = [location, path].filter { !$0.isEmpty }.joined(separator: "  ")
        return "\(d), \(t)\(tail.isEmpty ? "" : ": \(tail)")"
    }

    private func icon(_ kind: String) -> String {
        switch kind {
        case "finding.discovered": "magnifyingglass"
        case "redaction.applied": "checkmark.seal.fill"
        default: "circle.fill"
        }
    }
    private func tint(_ kind: String) -> Color {
        switch kind {
        case "redaction.applied": .green
        case "finding.discovered": .yellow
        default: .gray
        }
    }
}
