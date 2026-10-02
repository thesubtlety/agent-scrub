import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel
    enum Tab: String, CaseIterable, Identifiable {
        case overview = "Overview", findings = "Discovered secrets", coverage = "Coverage", history = "Audit log"
        var id: String { rawValue }
    }
    @State private var tab: Tab = .overview

    var body: some View {
        NavigationSplitView {
            List(Tab.allCases, selection: $tab) { t in Text(t.rawValue).tag(t) }
                .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            switch tab {
            case .overview: OverviewView(model: model)
            case .findings: DiscoveredSecretsView(model: model)
            case .coverage: CoverageView(model: model)
            case .history: HistoryView(model: model)
            }
        }
        .onChange(of: model.navigateTo) { if model.navigateTo != nil { tab = .findings } }
        .onAppear { if model.navigateTo != nil { tab = .findings } }   // nav set before the window existed
        .frame(minWidth: 760, minHeight: 480)
    }
}
