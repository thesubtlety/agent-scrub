import AppKit
import Combine
import SwiftUI
import StoreMonitoring
import HistoryGuardCore

/// Owns the menu bar status item. Created immediately at launch so the item always appears, then the
/// live model is attached once the (potentially slow) startup finishes. Maps status to a distinct,
/// coloured glyph — no shield, and never a black template that blends into the menu bar.
@MainActor
final class StatusItemController {
    private let item: NSStatusItem
    private let popover = NSPopover()
    private let notePopover = NSPopover()
    private var noteDismiss: DispatchWorkItem?
    private var cancellable: AnyCancellable?
    private weak var liveModel: AppModel?
    private let openWindow: () -> Void

    init(openWindow: @escaping () -> Void) {
        self.openWindow = openWindow
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        popover.behavior = .transient
        if let button = item.button {
            button.action = #selector(toggle)
            button.target = self
        }
        setFixedIcon()
        popover.contentViewController = NSHostingController(rootView: SimpleContent(message: "Starting…"))
    }

    /// Wire the item to the live monitor once startup succeeds.
    func attach(model: AppModel) {
        liveModel = model
        // Open the window on the next run-loop turn, after the popover closes — creating a window and
        // calling makeKeyAndOrderFront synchronously inside the SwiftUI button action is a reentrant
        // AppKit/SwiftUI update that corrupts state and crashes.
        let open = openWindow
        let deferredOpen: () -> Void = { [weak self] in
            self?.popover.performClose(nil)
            DispatchQueue.main.async { open() }
        }
        popover.contentViewController = NSHostingController(
            rootView: MenuContent(model: model, openWindow: deferredOpen))
        // The icon is fixed (set at init); no status→icon subscription, so it never flickers.
    }

    /// Startup failed (e.g. the Keychain was unavailable); keep the item visible and say so.
    func showError(_ message: String) {
        cancellable = nil
        setFixedIcon()
        popover.contentViewController = NSHostingController(rootView: SimpleContent(message: message))
    }

    /// One fixed, monochrome template icon. It never changes with status, so it can't flicker; the status itself
    /// is shown in the popover and the window. `text.redaction` (a line with a redaction bar) is on-brand.
    private func setFixedIcon() {
        guard let button = item.button else { return }
        let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
        let image = (NSImage(systemSymbolName: "text.redaction", accessibilityDescription: "Agent Scrub")
                     ?? NSImage(systemSymbolName: "doc.text", accessibilityDescription: "Agent Scrub"))?
            .withSymbolConfiguration(config)
        image?.isTemplate = true   // adapts to menu bar light/dark, non-colored
        button.image = image
        button.contentTintColor = nil
    }

    @objc private func toggle() {
        guard let button = item.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    /// Drop a short, self-dismissing note from the menu bar when a new secret is found — a lightweight alert that
    /// doesn't depend on macOS notification permissions and never changes the (deliberately static) icon. Clicking
    /// it opens the app focused on the secret; its menu offers quick triage.
    func showNote(_ secret: SecretIdentity, count: Int) {
        guard let button = item.button, let model = liveModel else { return }
        noteDismiss?.cancel()
        if popover.isShown { popover.performClose(nil) }
        let dismiss: () -> Void = { [weak self] in self?.noteDismiss?.cancel(); self?.notePopover.performClose(nil) }
        let review: () -> Void = { [weak self] in
            self?.notePopover.performClose(nil)
            model.focus(secret)                                   // set navigation first…
            DispatchQueue.main.async { self?.openWindow() }       // …then open the window to it
        }
        notePopover.behavior = .transient
        notePopover.contentViewController = NSHostingController(
            rootView: NoteContent(model: model, secret: secret, count: count, onReview: review, onDismiss: dismiss))
        if !notePopover.isShown {
            notePopover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
        let work = DispatchWorkItem { [weak self] in self?.notePopover.performClose(nil) }
        noteDismiss = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 8, execute: work)   // longer: it's interactive now
    }
}

private struct NoteContent: View {
    @ObservedObject var model: AppModel
    let secret: SecretIdentity
    let count: Int
    let onReview: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Button(action: onReview) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "key.horizontal.fill").foregroundStyle(.orange).font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(count == 1 ? "New secret found" : "\(count) new secrets found").font(.callout.bold())
                        Text(secret.label).font(.caption)
                        Text(secret.maskedDisplay).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            .buttonStyle(.plain)
            Spacer(minLength: 4)
            Menu {
                Button("Review in app") { onReview() }
                Divider()
                Button("Always redact") { act(.alwaysRedact) }
                Button("Not a secret") { act(.falsePositive) }
                Button("Always keep") { act(.alwaysKeep) }
            } label: { Image(systemName: "ellipsis.circle") }
                .menuStyle(.borderlessButton).fixedSize()
        }
        .padding(12).frame(width: 320, alignment: .leading)
    }

    private func act(_ policy: RetentionPolicy) {
        model.setPolicy(policy, for: secret)
        onDismiss()
    }
}

private struct MenuContent: View {
    @ObservedObject var model: AppModel
    let openWindow: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(model.state.headline).font(.headline)
            if model.state.scanning {
                HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Scanning…") }
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("\(model.state.stores.filter(\.present).count) stores verified")
                    .foregroundStyle(.secondary).font(.caption)
            }
            Divider()
            Button("Open Agent Scrub") { openWindow() }
            Button("Scan Now") { model.scanNow() }
            Button("Quit") { NSApp.terminate(nil) }
        }
        .padding(12).frame(width: 260)
    }
}

private struct SimpleContent: View {
    let message: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Agent Scrub").font(.headline)
            Text(message).font(.caption).foregroundStyle(.secondary)
            Divider()
            Button("Quit") { NSApp.terminate(nil) }
        }
        .padding(12).frame(width: 260)
    }
}
