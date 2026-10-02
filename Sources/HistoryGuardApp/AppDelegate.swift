import AppKit
import UserNotifications
import HistoryGuardCore
import SecretDetection
import ClaudeCodeAdapter
import CodexAdapter
import GeminiAdapter
import VSCodeAdapter
import ClineAdapter
import AiderAdapter
import ContinueAdapter
import PiAdapter
import StoreMonitoring
import HistoryGuardDB
import KeychainSupport

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var statusController: StatusItemController?
    private var windowController: MainWindowController?
    private var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Run as a regular app so it has a Dock icon and the standard top-left menu (with Quit) — an accessory
        // app gets neither, which left no obvious way to quit or reopen it.
        NSApp.setActivationPolicy(.regular)
        installMainMenu()
        if Bundle.main.bundleIdentifier != nil { UNUserNotificationCenter.current().delegate = self }
        Notifier.requestAuthorization()

        // Show the menu bar item immediately so it is always present, then build everything else off the
        // main thread — the Keychain read can block on a system prompt and must never freeze the UI.
        let status = StatusItemController { [weak self] in self?.showWindow() }
        self.statusController = status

        Task.detached { [weak self] in
            do {
                let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                          appropriateFor: nil, create: true)
                    .appendingPathComponent("History Guard", isDirectory: true)
                let store = try StateStore(url: support.appendingPathComponent("state.sqlite"))
                let key = try KeychainInstallationKeyStore().loadOrCreate()
                let scanner = SecretScanner(catalog: try RuleCatalog.bundled())
                let fingerprinter = Fingerprinter(key: key)

                let adapters: [any AgentAdapter] = [ClaudeCodeAdapter(), CodexAdapter(), GeminiAdapter(), VSCodeAdapter(), ClineAdapter(), AiderAdapter(), ContinueAdapter(), PiAdapter()]
                var pairs: [(adapter: any AgentAdapter, installation: AgentInstallation)] = []
                for a in adapters {
                    for i in await a.discoverInstallations() { pairs.append((adapter: a, installation: i)) }
                }

                // `store` is handed to the actor, which owns it exclusively; it is not used here after.
                let service = MonitorService(pairs: pairs, scanner: scanner, fingerprinter: fingerprinter,
                                             state: store, changeSource: FSEventsChangeSource())
                let policyStore = FilePolicyStore(url: support.appendingPathComponent("policies.json"))
                await self?.finishLaunching(service: service, policyStore: policyStore, status: status)
            } catch {
                NSLog("Agent Scrub failed to start: \(error)")
                await status.showError("Couldn’t start — \(error)")
            }
        }
    }

    private func finishLaunching(service: MonitorService, policyStore: FilePolicyStore, status: StatusItemController) {
        let model = AppModel(service: service, policyStore: policyStore)
        self.model = model
        model.onNewSecrets = { [weak status] secret, count in status?.showNote(secret, count: count) }
        status.attach(model: model)
        windowController = MainWindowController(model: model)
        // Open the window on launch. The menu bar item can be hidden under the notch when the bar is full, and
        // an accessory app has no Dock icon, so the window is the reliable way in.
        showWindow()
    }

    /// Re-opening the app (double-click in Finder, a second `open`) brings the window back — the main escape
    /// hatch when the status item isn't reachable.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return true
    }

    /// Show the banner even when the app is in the foreground (otherwise macOS suppresses it).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    private func showWindow() { windowController?.show() }

    /// A minimal standard menu: the app menu (About / Hide / Quit) and an Edit menu so copy/paste and Select All
    /// work in the reveal fields. AppKit titles the first submenu with the bundle name automatically.
    private func installMainMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        appMenu.addItem(withTitle: "About Agent Scrub",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Agent Scrub", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Quit Agent Scrub", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let editItem = NSMenuItem()
        main.addItem(editItem)
        let editMenu = NSMenu(title: "Edit")
        editItem.submenu = editMenu
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        NSApp.mainMenu = main
    }
}
