import AppKit

@MainActor
func runApp() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate                 // delegate is weak; this frame retains it for the app's life
    app.setActivationPolicy(.accessory)     // menu bar only, no dock icon
    app.run()
}

// Process entry runs on the main thread; enter the main actor and start the app.
MainActor.assumeIsolated { runApp() }
