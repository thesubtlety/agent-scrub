import SwiftUI
import HistoryGuardCore
import StoreMonitoring

struct OverviewView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        let s = model.state
        List {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text(s.headline).font(.title2).bold()
                    // A spinner only until the first scan verifies — a one-time, stable state, so it can't flicker.
                    if s.lastVerified == nil {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Scanning your AI memory…") }
                            .foregroundStyle(.secondary)
                    }
                    Text("\(s.stores.filter(\.present).count) configured stores")
                        .foregroundStyle(.secondary)
                    if let last = s.lastVerified {
                        Text("Last verified \(last.formatted(.relative(presentation: .named)))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }

            Section("Protection (lifetime)") {
                statRow("Copies redacted", s.lifetimeCopiesRedacted)
                statRow("Secrets cleared", s.lifetimeSecretsRedacted)
                if !s.activeArtifacts.isEmpty { statRow("Files in an active session", s.activeArtifacts.count) }
            }

            if !s.secrets.isEmpty {
                Section("By type") {
                    ForEach(byKind(s), id: \.kind) { navRow($0.kind.displayName, $0.count, .kind($0.kind)) }
                }
                Section("By project / folder") {
                    ForEach(byProject(s), id: \.id) { navRow($0.label, $0.count, .project($0.id)) }
                }
                Section("By app") {
                    ForEach(byApp(s), id: \.id) { navRow($0.label, $0.count, .app($0.id)) }
                }
            }
        }
    }

    /// A clickable stat row that opens Discovered Secrets filtered to this dimension.
    @ViewBuilder private func navRow(_ label: String, _ count: Int, _ filter: SecretFilter) -> some View {
        Button { model.navigateTo = filter } label: {
            HStack {
                statRow(label, count)
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
        }.buttonStyle(.plain)
    }

    private func statRow(_ label: String, _ count: Int) -> some View {
        HStack {
            Text(label).lineLimit(1).truncationMode(.middle)
            Spacer()
            Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
        }
    }

    // Dismissed ("not a secret") findings are excluded from the overview — they aren't secrets.
    private func isDismissed(_ fp: SecretFingerprint) -> Bool { model.policy(for: fp) == .falsePositive }

    private func byKind(_ s: MonitorState) -> [(kind: SecretKind, count: Int)] {
        Dictionary(grouping: s.secrets.filter { !isDismissed($0.fingerprint) }, by: \.kind)
            .map { (kind: $0.key, count: $0.value.count) }
            .sorted { $0.count > $1.count }
    }

    private func byProject(_ s: MonitorState) -> [(id: String, label: String, count: Int)] {
        var counts: [String: Int] = [:]
        for o in s.occurrences where !isDismissed(o.fingerprint) {
            counts[o.projectPath ?? o.artifactURL.deletingLastPathComponent().lastPathComponent, default: 0] += 1
        }
        return counts.map { (id: $0.key, label: $0.key, count: $0.value) }
            .sorted { $0.count > $1.count }.prefix(10).map { $0 }
    }

    private func byApp(_ s: MonitorState) -> [(id: String, label: String, count: Int)] {
        var counts: [String: Int] = [:]
        for o in s.occurrences where !isDismissed(o.fingerprint) { counts[AppLabel.of(o), default: 0] += 1 }
        return counts.map { (id: $0.key, label: $0.key, count: $0.value) }.sorted { $0.count > $1.count }
    }
}
