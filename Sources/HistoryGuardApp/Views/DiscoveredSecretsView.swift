import Foundation
import AppKit
import SwiftUI
import HistoryGuardCore
import StoreMonitoring

private enum Bucket: String, CaseIterable, Identifiable {
    case needsAttention = "Needs attention", kept = "Kept", dismissed = "Dismissed", all = "All"
    var id: String { rawValue }
}
private enum SortKey: String, CaseIterable, Identifiable {
    case confidence = "Confidence", copies = "Copies", lastSeen = "Last seen"
    var id: String { rawValue }
}

struct DiscoveredSecretsView: View {
    @ObservedObject var model: AppModel
    @State private var bucket: Bucket = .needsAttention
    @State private var sort: SortKey = .confidence
    @State private var kindFilter: SecretKind?
    @State private var appFilter: String?
    @State private var projectFilter: String?
    @State private var query = ""
    @State private var selected: UUID?
    @State private var pendingRedact: SecretIdentity?
    @State private var pendingForce: SecretIdentity?
    @State private var resultMessage: String?
    @State private var isRedacting = false
    @State private var toast: String?
    @State private var toastID = 0
    @AppStorage("alwaysRevealValues") private var alwaysReveal = false

    var body: some View { content }

    func showToast(_ message: String) {
        toastID += 1
        let id = toastID
        withAnimation(.easeOut(duration: 0.2)) { toast = message }
        Task {
            try? await Task.sleep(nanoseconds: 1_900_000_000)
            if toastID == id { withAnimation { toast = nil } }
        }
    }

    /// Apply a triage decision and confirm it with a toast, so it's clear something happened.
    private func triage(_ policy: RetentionPolicy?, _ verb: String, _ secret: SecretIdentity) {
        model.setPolicy(policy, for: secret)
        showToast("\(verb) “\(secret.label)”")
    }

    private var content: some View {
        let counts = copyCounts()
        let locations = locationSummaries()
        let apps = appSummaries()
        let rows = filteredSorted(counts: counts)
        let shown = selected ?? rows.first?.id   // default to the first secret so the pane isn't empty grey
        return VStack(spacing: 0) {
            toolbar
            Divider()
            HSplitView {
                listPane(rows: rows, counts: counts, locations: locations, apps: apps)
                detailPane(id: shown)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)   // fill the window; keep the toolbar pinned to the top
        }
        .searchable(text: $query, placement: .toolbar, prompt: "Search label, value, kind")
        .onAppear(perform: consumeNavigation)
        .onChange(of: model.navigateTo) { consumeNavigation() }
        .navigationTitle("Discovered secrets")
        .confirmationDialog("Redact this secret?",
                            isPresented: Binding(get: { pendingRedact != nil }, set: { if !$0 { pendingRedact = nil } }),
                            presenting: pendingRedact, actions: redactActions, message: redactMessage)
        .confirmationDialog("Force-redact a binary copy?",
                            isPresented: Binding(get: { pendingForce != nil }, set: { if !$0 { pendingForce = nil } }),
                            presenting: pendingForce, actions: forceActions, message: forceMessage)
        .alert("Redaction", isPresented: Binding(get: { resultMessage != nil }, set: { if !$0 { resultMessage = nil } })) {
            Button("OK") { resultMessage = nil }
        } message: { Text(resultMessage ?? "") }
        .overlay { if isRedacting { redactingHUD } }
        .overlay(alignment: .bottom) {
            if let toast {
                Text(toast).font(.callout)
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .overlay(Capsule().strokeBorder(.separator))
                    .padding(.bottom, 18)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
    }

    private var redactingHUD: some View {
        ZStack {
            Color.black.opacity(0.2).ignoresSafeArea()
            VStack(spacing: 10) {
                ProgressView()
                Text("Redacting…").font(.callout)
            }
            .padding(24)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        }
    }

    /// Runs a redaction with a working indicator, then shows the result. Shared by both confirm buttons so the
    /// several-second scan+rewrite+verify never looks like nothing happened.
    private func performRedact(_ secret: SecretIdentity, allowActive: Bool, allowBinaryForce: Bool = false) {
        pendingRedact = nil; pendingForce = nil
        isRedacting = true
        Task {
            let summary = await model.redact(secret, allowActive: allowActive, allowBinaryForce: allowBinaryForce)
            isRedacting = false
            resultMessage = resultText(secret, summary)
        }
    }

    /// Apply (and clear) a filter requested from the Overview, showing all buckets so the matching secrets are
    /// visible regardless of triage state. A new request replaces any existing dimension filters.
    private func consumeNavigation() {
        guard let req = model.navigateTo else { return }
        kindFilter = nil; appFilter = nil; projectFilter = nil
        var focus: UUID?
        switch req {
        case let .kind(k): kindFilter = k
        case let .app(a): appFilter = a
        case let .project(p): projectFilter = p
        case let .secret(fp): focus = model.state.secrets.first { $0.fingerprint == fp }?.id
        }
        bucket = .all
        selected = focus
        model.navigateTo = nil
    }

    private var toolbar: some View {
        HStack {
            Picker("", selection: $bucket) { ForEach(Bucket.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).frame(maxWidth: 420).labelsHidden()
            Spacer()
            if let p = projectFilter {
                Button { projectFilter = nil } label: { Label("Project: \(p)  ✕", systemImage: "folder") }
                    .buttonStyle(.bordered).controlSize(.small).fixedSize()
            }
            Menu {
                Picker("Type", selection: $kindFilter) {
                    Text("All types").tag(SecretKind?.none)
                    ForEach(availableKinds(), id: \.self) { k in Text(k.displayName).tag(SecretKind?.some(k)) }
                }
            } label: { Label(kindFilter.map { "Type: \($0.displayName)" } ?? "Type: All", systemImage: "tag") }
                .fixedSize()
            Menu {
                Picker("App", selection: $appFilter) {
                    Text("All apps").tag(String?.none)
                    ForEach(availableApps(), id: \.self) { a in Text(a).tag(String?.some(a)) }
                }
            } label: { Label(appFilter.map { "App: \($0)" } ?? "App: All", systemImage: "app.badge") }
                .fixedSize()
            Menu {
                Picker("Sort by", selection: $sort) { ForEach(SortKey.allCases) { Text($0.rawValue).tag($0) } }
            } label: { Label("Sort: \(sort.rawValue)", systemImage: "arrow.up.arrow.down") }
                .fixedSize()
            Toggle(isOn: $alwaysReveal) { Label("Reveal values", systemImage: alwaysReveal ? "eye" : "eye.slash") }
                .toggleStyle(.button).fixedSize()
                .help("Always show secret values without clicking Reveal each time")
        }
        .padding(8)
    }

    @ViewBuilder private func listPane(rows: [SecretIdentity], counts: [SecretFingerprint: Int],
                                       locations: [SecretFingerprint: String], apps: [SecretFingerprint: String]) -> some View {
        Group {
            if rows.isEmpty {
                ContentUnavailableView(emptyTitle, systemImage: "checkmark.seal", description: Text("Nothing in this view."))
            } else {
                List(rows, id: \.id, selection: $selected) { secret in
                    row(secret, copies: counts[secret.fingerprint] ?? 0, location: locations[secret.fingerprint] ?? "",
                        app: apps[secret.fingerprint] ?? "")
                }
            }
        }
        .frame(minWidth: 340, idealWidth: 420, maxHeight: .infinity)
    }

    @ViewBuilder private func detailPane(id: UUID?) -> some View {
        Group {
            if let id {
                SecretDetailView(model: model, secretID: id,
                                 onRedact: { pendingRedact = $0 }, onForceRedact: { pendingForce = $0 },
                                 onToast: { showToast($0) })
            } else { ContentUnavailableView("No discovered secrets", systemImage: "checkmark.seal") }
        }
        .frame(minWidth: 440, idealWidth: 580, maxHeight: .infinity)
    }

    @ViewBuilder private func redactActions(_ secret: SecretIdentity) -> some View {
        let copies = model.state.occurrences.filter { $0.fingerprint == secret.fingerprint }.count
        Button("Redact \(copies) cop\(copies == 1 ? "y" : "ies")", role: .destructive) {
            performRedact(secret, allowActive: false)
        }
        Button("Redact including active sessions", role: .destructive) {
            performRedact(secret, allowActive: true)
        }
        Button("Cancel", role: .cancel) { pendingRedact = nil }
    }

    private func redactMessage(_ secret: SecretIdentity) -> Text {
        Text("Overwrites the secret in place in your local files — this can't be undone. It does NOT remove copies already sent to providers or in backups/snapshots. By default copies in a live session are skipped; use \"including active sessions\" to rewrite those too (safe for append-only transcripts).")
    }

    @ViewBuilder private func forceActions(_ secret: SecretIdentity) -> some View {
        Button("Force-redact", role: .destructive) { performRedact(secret, allowActive: true, allowBinaryForce: true) }
        Button("Cancel", role: .cancel) { pendingForce = nil }
    }

    private func forceMessage(_ secret: SecretIdentity) -> Text {
        Text("A copy of this secret is inside a binary record we can't fully parse (like Cursor's msgpack chat blob). Force-redact overwrites the secret's exact bytes in place — the record stays the same size and the database stays valid — but unlike text we can't re-parse the binary afterward to confirm its structure. It removes the copy only when those exact bytes appear exactly once in the record. This can't be undone.")
    }

    private func resultText(_ secret: SecretIdentity, _ o: RedactionSummary) -> String {
        var parts: [String] = []
        if o.applied > 0 { parts.append("Redacted \(o.applied) cop\(o.applied == 1 ? "y" : "ies") of \(secret.label).") }
        if o.deferred > 0 {
            let reasons = o.deferredReasons.map { "\($0.value) × \($0.key)" }.sorted().joined(separator: "; ")
            parts.append("\(o.deferred) couldn’t be removed yet: \(reasons).")
        }
        if o.failed > 0 { parts.append("\(o.failed) failed.") }
        if o.isVerifiedClean {
            parts.append("No copies remain.")
        } else if o.remaining > 0 {
            // When everything left is deferred, say so instead of a bare "still remain".
            let allDeferred = o.remaining == o.deferred && o.deferred > 0
            parts.append(allDeferred ? "Those \(o.remaining) are the copies still on disk."
                                     : "\(o.remaining) cop\(o.remaining == 1 ? "y" : "ies") still remain.")
        }
        if parts.isEmpty { parts.append("Nothing to redact for \(secret.label).") }
        return parts.joined(separator: " ")
    }

    @ViewBuilder private func row(_ secret: SecretIdentity, copies: Int, location: String, app: String) -> some View {
        if let rec = model.recentlyRedacted[secret.fingerprint] {
            redactedRow(secret, rec)
        } else {
            liveRow(secret, copies: copies, location: location, app: app)
        }
    }

    @ViewBuilder private func redactedRow(_ secret: SecretIdentity, _ rec: AppModel.RedactedRecord) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 2) {
                Text(secret.label).bold()
                Text("\(secret.kind.displayName)  ·  \(rec.copies) cop\(rec.copies == 1 ? "y" : "ies") redacted")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text("→ \(model.redactedMarker(for: secret))…")
                    .font(.caption).foregroundStyle(.green).lineLimit(1).truncationMode(.middle)
                if !rec.locations.isEmpty {
                    Text(rec.locations.count <= 1 ? rec.locations[0] : "\(rec.locations[0])  +\(rec.locations.count - 1) more")
                        .font(.caption2).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
            Text("Redacted").font(.caption2).foregroundStyle(.green)
                .padding(.horizontal, 6).padding(.vertical, 2).background(.green.opacity(0.15), in: Capsule())
        }
    }

    @ViewBuilder private func liveRow(_ secret: SecretIdentity, copies: Int, location: String, app: String) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(secret.label).bold()
                Text("\(secret.maskedDisplay)  ·  \(copies) cop\(copies == 1 ? "y" : "ies")  ·  \(secret.confidence.rawValue)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !app.isEmpty || !location.isEmpty {
                    let whereText = [app, location].filter { !$0.isEmpty }.joined(separator: "  ·  ")
                    Label(whereText, systemImage: "macwindow")
                        .font(.caption2).foregroundStyle(.tertiary).labelStyle(.titleAndIcon)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
            if model.state.hasLiveCopy(secret.fingerprint) {
                Label("Live", systemImage: "dot.radiowaves.left.and.right").font(.caption2).foregroundStyle(.orange)
                    .labelStyle(.titleAndIcon).padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.orange.opacity(0.15), in: Capsule())
                    .help("A copy is in an active session and won't be redacted until it ends")
            }
            if let badge = badge(for: secret.fingerprint) {
                Text(badge).font(.caption2).padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
            }
            rowMenu(secret)
        }
    }

    @ViewBuilder private func rowMenu(_ secret: SecretIdentity) -> some View {
        Menu {
            Button("Redact now…", role: .destructive) { pendingRedact = secret }
            Button("Always redact") { triage(.alwaysRedact, "Will auto-redact", secret) }
            Divider()
            Button("Not a secret") { triage(.falsePositive, "Dismissed", secret) }
            Button("Always keep") { triage(.alwaysKeep, "Keeping", secret) }
            Menu("Keep for…") {
                Button("1 hour") { triage(.keepUntil(Date().addingTimeInterval(3600)), "Keeping for 1 hour", secret) }
                Button("1 day") { triage(.keepUntil(Date().addingTimeInterval(86_400)), "Keeping for 1 day", secret) }
                Button("7 days") { triage(.keepUntil(Date().addingTimeInterval(7 * 86_400)), "Keeping for 7 days", secret) }
            }
            if model.policy(for: secret.fingerprint) != nil {
                Divider()
                Button("Clear decision") { triage(nil, "Cleared decision for", secret) }
            }
        } label: { Image(systemName: "ellipsis.circle") }
            .menuStyle(.borderlessButton).fixedSize()
    }

    private func copyCounts() -> [SecretFingerprint: Int] {
        var c: [SecretFingerprint: Int] = [:]
        for o in model.state.occurrences { c[o.fingerprint, default: 0] += 1 }
        return c
    }

    /// The app(s) a secret's copies live in — e.g. "Cursor", or "Cursor  +1" when it spans more than one.
    private func appSummaries() -> [SecretFingerprint: String] {
        var byFP: [SecretFingerprint: Set<String>] = [:]
        for o in model.state.occurrences { byFP[o.fingerprint, default: []].insert(AppLabel.of(o)) }
        var out: [SecretFingerprint: String] = [:]
        for (fp, apps) in byFP {
            let sorted = apps.sorted()
            out[fp] = sorted.count <= 1 ? (sorted.first ?? "") : "\(sorted[0])  +\(sorted.count - 1)"
        }
        return out
    }

    /// A short "where" label per secret: the project(s) or file(s) its copies live in.
    private func locationSummaries() -> [SecretFingerprint: String] {
        var byFP: [SecretFingerprint: Set<String>] = [:]
        for o in model.state.occurrences {
            let loc = o.projectPath ?? o.artifactURL.deletingLastPathComponent().lastPathComponent
            byFP[o.fingerprint, default: []].insert(loc)
        }
        var out: [SecretFingerprint: String] = [:]
        for (fp, locs) in byFP {
            let sorted = locs.sorted()
            out[fp] = sorted.count <= 1 ? (sorted.first ?? "") : "\(sorted[0])  +\(sorted.count - 1) more"
        }
        return out
    }

    private func bucket(for fingerprint: SecretFingerprint) -> Bucket {
        switch model.policy(for: fingerprint) {
        case .falsePositive: .dismissed
        case .alwaysKeep: .kept
        case let .keepUntil(date): date > Date() ? .kept : .needsAttention
        case .redactNow, .redactWhenSessionEnds, .alwaysRedact, nil: .needsAttention
        }
    }

    private func badge(for fingerprint: SecretFingerprint) -> String? {
        switch model.policy(for: fingerprint) {
        case .falsePositive: "Dismissed"
        case .alwaysKeep: "Kept"
        case let .keepUntil(date): date > Date() ? "Keep until \(date.formatted(date: .abbreviated, time: .omitted))" : nil
        case .alwaysRedact: "Will redact"
        case .redactWhenSessionEnds: "Redact at session end"
        case .redactNow: "Redact"
        case nil: nil
        }
    }

    private var emptyTitle: String {
        switch bucket {
        case .needsAttention: "No secrets need attention"
        case .kept: "Nothing kept"
        case .dismissed: "Nothing dismissed"
        case .all: "No discovered secrets"
        }
    }

    /// The distinct secret kinds currently present, for the type filter menu.
    private func availableKinds() -> [SecretKind] {
        Array(Set(model.state.secrets.map(\.kind))).sorted { $0.displayName < $1.displayName }
    }
    /// The distinct apps (adapter ids) that have findings, for the app filter menu.
    private func availableApps() -> [String] {
        Array(Set(model.state.occurrences.map(AppLabel.of))).sorted()
    }
    private func occProject(_ o: SecretOccurrence) -> String {
        o.projectPath ?? o.artifactURL.deletingLastPathComponent().lastPathComponent
    }

    private func filteredSorted(counts: [SecretFingerprint: Int]) -> [SecretIdentity] {
        let q = query.lowercased()
        // A secret matches an app/project filter if any of its copies lives there.
        let fpsInApp: Set<SecretFingerprint>? = appFilter.map { a in
            Set(model.state.occurrences.filter { AppLabel.of($0) == a }.map(\.fingerprint))
        }
        let fpsInProject: Set<SecretFingerprint>? = projectFilter.map { p in
            Set(model.state.occurrences.filter { occProject($0) == p }.map(\.fingerprint))
        }
        var rows = model.state.secrets.filter { s in
            let inBucket = bucket == .all || bucket(for: s.fingerprint) == bucket
            let kindOK = kindFilter == nil || s.kind == kindFilter
            let appOK = fpsInApp?.contains(s.fingerprint) ?? true
            let projOK = fpsInProject?.contains(s.fingerprint) ?? true
            let searchOK = q.isEmpty || s.label.lowercased().contains(q) || s.maskedDisplay.lowercased().contains(q)
                || s.kind.rawValue.lowercased().contains(q)
            // Low-confidence, undecided findings don't demand attention — show them only under All.
            let hiddenLow = bucket == .needsAttention && model.policy(for: s.fingerprint) == nil && s.confidence < .medium
            return inBucket && kindOK && appOK && projOK && searchOK && !hiddenLow
        }
        switch sort {
        case .confidence: rows.sort { $0.confidence != $1.confidence ? $0.confidence > $1.confidence : $0.alias < $1.alias }
        case .copies: rows.sort { (counts[$0.fingerprint] ?? 0) > (counts[$1.fingerprint] ?? 0) }
        case .lastSeen: rows.sort { $0.lastSeen > $1.lastSeen }
        }
        // Keep this session's just-redacted secrets visible (they're no longer detected) as a green confirmation,
        // honouring the type filter and search. They sit at the top so the result of the action is obvious.
        let live = Set(rows.map(\.fingerprint))
        let allRedacted: [SecretIdentity] = model.recentlyRedacted.values.map(\.identity)
        var redacted: [SecretIdentity] = allRedacted.filter { !live.contains($0.fingerprint) }
        if let kindFilter { redacted = redacted.filter { $0.kind == kindFilter } }
        if !q.isEmpty {
            redacted = redacted.filter { $0.label.lowercased().contains(q) || $0.kind.rawValue.lowercased().contains(q) }
        }
        redacted.sort { $0.alias < $1.alias }
        return redacted + rows
    }
}

struct SecretDetailView: View {
    @ObservedObject var model: AppModel
    let secretID: UUID
    var onRedact: (SecretIdentity) -> Void = { _ in }
    var onForceRedact: (SecretIdentity) -> Void = { _ in }
    var onToast: (String) -> Void = { _ in }
    @State private var excerpts: [UUID: String] = [:]
    @State private var revealedValue: String?
    @State private var jwtDecoded: String?
    @AppStorage("alwaysRevealValues") private var alwaysReveal = false

    var body: some View {
        let redactedRecord = model.recentlyRedacted.values.first { $0.identity.id == secretID }
        let secret = model.state.secrets.first { $0.id == secretID } ?? redactedRecord?.identity
        let isRedacted = redactedRecord != nil
        let occ = model.state.occurrences.filter { $0.secretID == secretID }
        let storeName = Dictionary(model.state.stores.map { ($0.storeID, $0.displayName) },
                                   uniquingKeysWith: { first, _ in first })
        return VStack(alignment: .leading, spacing: 0) {
            if let s = secret, let rec = redactedRecord {
                redactedBanner(s, rec)
            } else if let s = secret {
                liveHeader(s, occCount: occ.count)
                actionBar(s).controlSize(.small).padding(.horizontal).padding(.bottom, 8)
                Divider()
            }
            List(occ) { o in occurrenceRow(o, storeName: storeName) }
        }
        .task(id: secretID) { await loadExcerpts() }
        .onChange(of: alwaysReveal) {
            if alwaysReveal { Task { await loadValue() } } else { revealedValue = nil }
        }
    }

    @ViewBuilder private func redactedBanner(_ s: SecretIdentity, _ rec: AppModel.RedactedRecord) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Redacted", systemImage: "checkmark.seal.fill").foregroundStyle(.green).font(.title3.bold())
            Text(s.label).font(.headline)
            HStack(spacing: 16) {
                Label("\(rec.copies) cop\(rec.copies == 1 ? "y" : "ies")", systemImage: "doc.on.doc")
                Label(s.kind.displayName, systemImage: "tag")
            }.font(.caption).foregroundStyle(.secondary)
            if !rec.locations.isEmpty {
                Text("In: \(rec.locations.joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Text("The value in your files is now:").font(.caption).foregroundStyle(.secondary).padding(.top, 4)
            Text("\(model.redactedMarker(for: s))••••")
                .font(.system(.body, design: .monospaced)).foregroundStyle(.green).textSelection(.enabled)
            Text("It’ll stop showing here after the next launch.").font(.caption).foregroundStyle(.secondary)
            Spacer()
        }.padding()
    }

    @ViewBuilder private func liveHeader(_ s: SecretIdentity, occCount: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(s.label).font(.title3).bold()
            Text(s.maskedDisplay).font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
            HStack(spacing: 16) {
                Label("\(occCount) local cop\(occCount == 1 ? "y" : "ies")", systemImage: "doc.on.doc")
                Label(s.confidence.rawValue, systemImage: "speedometer")
            }.font(.caption).foregroundStyle(.secondary)
            Text("First seen \(s.firstSeen.formatted(date: .abbreviated, time: .shortened))  ·  last seen \(s.lastSeen.formatted(date: .abbreviated, time: .shortened))")
                .font(.caption).foregroundStyle(.secondary)
            valueSection(s)
        }.padding()
    }

    @ViewBuilder private func valueSection(_ s: SecretIdentity) -> some View {
        if let value = revealedValue {
            HStack(alignment: .top, spacing: 8) {
                Text(value).font(.system(.caption, design: .monospaced)).foregroundStyle(.red)
                    .lineLimit(6).textSelection(.enabled)
                if !alwaysReveal { Button("Hide") { revealedValue = nil }.buttonStyle(.link).font(.caption) }
            }
        } else {
            Button("Reveal value") { Task { await loadValue() } }.buttonStyle(.link).font(.caption)
        }
        if s.kind == .jwt {
            if let decoded = jwtDecoded {
                Text(decoded).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                    .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(6)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            } else {
                Button("Decode JWT") { Task { await decodeJWT() } }.buttonStyle(.link).font(.caption)
            }
        }
    }

    private func loadValue() async {
        guard let first = model.state.occurrences.first(where: { $0.secretID == secretID }) else { return }
        revealedValue = await model.revealedValue(for: first)
            ?? "(file changed since scan — reopen to re-read)"
    }

    private func decodeJWT() async {
        if revealedValue == nil || revealedValue?.hasPrefix("(") == true { await loadValue() }
        guard let v = revealedValue else { return }
        jwtDecoded = JWT.decode(v) ?? "(couldn’t decode — not a well-formed JWT)"
    }

    @ViewBuilder private func occurrenceRow(_ o: SecretOccurrence, storeName: [StoreID: String]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(storeName[o.storeID] ?? o.storeID.rawValue).bold()
                if model.state.isLive(o) {
                    Label("active session", systemImage: "dot.radiowaves.left.and.right")
                        .font(.caption2).foregroundStyle(.orange)
                }
            }
            if let ex = excerpts[o.id] {
                Text(ex).font(.system(.caption, design: .monospaced)).foregroundStyle(.primary)
                    .lineLimit(2).textSelection(.enabled)
            }
            HStack(spacing: 8) {
                Text(o.artifactURL.path).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(o.artifactURL.path, forType: .string)
                } label: {
                    Label("Copy path", systemImage: "doc.on.doc").labelStyle(.iconOnly)
                }.buttonStyle(.link).help("Copy path")
                Button { NSWorkspace.shared.activateFileViewerSelecting([o.artifactURL]) } label: {
                    Label("Finder", systemImage: "folder").labelStyle(.iconOnly)
                }.buttonStyle(.link).help("Reveal in Finder")
                Button {
                    let folder = o.artifactURL.deletingLastPathComponent()
                    model.addExclusion(folder.path)
                    onToast("Excluded “\(folder.lastPathComponent)” — stop scanning this folder")
                } label: {
                    Label("Exclude folder", systemImage: "folder.badge.minus").labelStyle(.iconOnly)
                }.buttonStyle(.link).help("Stop scanning this folder (manage under Coverage)")
            }
            Text("\(AppLabel.of(o))  ·  \(String(describing: o.recordLocator))")
                .font(.caption2).foregroundStyle(.secondary)
            if let p = o.projectPath { Text("project \(p)").font(.caption2).foregroundStyle(.secondary) }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private func actionBar(_ s: SecretIdentity) -> some View {
        HStack(spacing: 8) {
            Button("Redact now…", role: .destructive) { onRedact(s) }
            if model.hasBinaryCopies(s) {
                Button("Force-redact binary copy…", role: .destructive) { onForceRedact(s) }
                    .help("A copy is inside a binary record we can't fully parse; overwrite its exact bytes in place")
            }
            Button("Always redact") { decide(.alwaysRedact, "Will auto-redact", s) }
            Button("Not a secret") { decide(.falsePositive, "Dismissed", s) }
            Button("Always keep") { decide(.alwaysKeep, "Keeping", s) }
            Menu("Keep for…") {
                Button("1 hour") { decide(.keepUntil(Date().addingTimeInterval(3600)), "Keeping for 1 hour", s) }
                Button("1 day") { decide(.keepUntil(Date().addingTimeInterval(86_400)), "Keeping for 1 day", s) }
                Button("7 days") { decide(.keepUntil(Date().addingTimeInterval(7 * 86_400)), "Keeping for 7 days", s) }
            }.fixedSize()
            if model.policy(for: s.fingerprint) != nil {
                Button("Clear") { decide(nil, "Cleared decision for", s) }
            }
            Spacer()
        }
    }

    private func decide(_ policy: RetentionPolicy?, _ verb: String, _ s: SecretIdentity) {
        model.setPolicy(policy, for: s)
        onToast("\(verb) “\(s.label)”")
    }

    /// Read a masked excerpt for each copy off the main thread (capped, since one secret can have many copies).
    private func loadExcerpts() async {
        revealedValue = nil   // don't carry one secret's revealed value onto the next
        jwtDecoded = nil
        if alwaysReveal { await loadValue() }
        let occ = model.state.occurrences.filter { $0.secretID == secretID }.prefix(100)
        var out: [UUID: String] = [:]
        for o in occ {
            if let excerpt = await model.contextExcerpt(for: o) { out[o.id] = excerpt }
        }
        excerpts = out
    }
}
