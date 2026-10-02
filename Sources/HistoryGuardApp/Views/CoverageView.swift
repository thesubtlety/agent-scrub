import SwiftUI
import AppKit
import HistoryGuardCore

struct CoverageView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        let gaps = model.state.gaps
        List {
            Section("Excluded folders — not scanned") {
                ForEach(model.exclusions, id: \.self) { path in
                    HStack {
                        Image(systemName: "folder.badge.minus").foregroundStyle(.secondary)
                        Text(path).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("Remove") { model.removeExclusion(path) }.buttonStyle(.link)
                    }
                }
                Button { chooseFolderToExclude() } label: { Label("Exclude a folder…", systemImage: "plus") }
            }
            Section("Stores") {
                ForEach(model.state.stores, id: \.storeID) { store in
                    HStack {
                        Image(systemName: store.gapCount == 0 ? "checkmark.circle" : "exclamationmark.triangle")
                            .foregroundStyle(store.gapCount == 0 ? .green : .yellow)
                        Text(store.displayName)
                        Spacer()
                        if store.gapCount > 0 {
                            Text("\(store.gapCount) gap\(store.gapCount == 1 ? "" : "s")").foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if !gaps.isEmpty {
                Section("Coverage gaps (\(gaps.count)) — things not fully scanned") {
                    ForEach(grouped(gaps), id: \.label) { group in
                        DisclosureGroup {
                            ForEach(Array(group.paths.prefix(50).enumerated()), id: \.offset) { _, p in
                                Text(p).font(.caption).foregroundStyle(.secondary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            if group.paths.count > 50 {
                                Text("… \(group.paths.count - 50) more").font(.caption2).foregroundStyle(.tertiary)
                            }
                        } label: {
                            Text("\(group.label)  ·  \(group.paths.count)")
                        }
                    }
                }
            }
        }
    }

    private func chooseFolderToExclude() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Exclude"
        panel.message = "Choose a folder to leave out of scanning. Its findings will be removed."
        if panel.runModal() == .OK, let url = panel.url { model.addExclusion(url.path) }
    }

    private func grouped(_ gaps: [CoverageGap]) -> [(label: String, paths: [String])] {
        var map: [String: [String]] = [:]
        for g in gaps { map[label(for: g.reason), default: []].append(g.path) }
        return map.map { (label: $0.key, paths: $0.value) }.sorted { $0.label < $1.label }
    }

    private func label(for reason: CoverageGap.Reason) -> String {
        switch reason {
        case .unknownStore: "Unknown store — not recognized, so not scanned"
        case .truncatedTail: "Truncated final record — file may be in use"
        case .corruptRecord: "Unparseable record"
        case .oversizeArtifact: "Oversize file — skipped"
        case .oversizeRecord: "Oversize record — skipped"
        case .skippedSymlink: "Symlink — not followed"
        case .binaryArtifact: "Binary file — skipped"
        case .unreadable: "Unreadable"
        case .unsupportedSchema: "Unsupported database schema — cannot scan safely"
        case .excludedByPolicy: "Excluded (auth/config store)"
        case .offsetsUnreliable: "Offsets unreliable"
        }
    }
}
