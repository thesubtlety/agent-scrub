import AppKit
import SwiftUI

/// Lazily creates and shows the main window hosting the SwiftUI sidebar.
@MainActor
final class MainWindowController {
    private var window: NSWindow?
    private let model: AppModel
    init(model: AppModel) { self.model = model }

    func show() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 760),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable],
                             backing: .buffered, defer: false)
            w.title = "Agent Scrub"
            w.isReleasedWhenClosed = false   // we hold a strong reference; don't let close over-release it
            w.contentMinSize = NSSize(width: 900, height: 520)
            w.contentViewController = NSHostingController(rootView: RootView(model: model))
            w.setContentSize(NSSize(width: 1280, height: 760))   // override the hosting view's tiny fitting size
            w.center()
            window = w
        }
        NSApp.activate()
        window?.makeKeyAndOrderFront(nil)
    }
}
