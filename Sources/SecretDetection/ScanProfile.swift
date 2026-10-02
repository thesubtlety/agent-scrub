import Foundation

/// Opt-in per-rule timing (HG_PROFILE=1). Development aid; records rule ids and durations only.
public final class ScanProfile: @unchecked Sendable {
    public static let shared = ScanProfile()
    public let enabled = ProcessInfo.processInfo.environment["HG_PROFILE"] == "1"
    private let lock = NSLock()
    private var nanos: [String: UInt64] = [:]
    private var windows: [String: Int] = [:]
    private var windowBytes: [String: Int] = [:]
    private var phases: [String: UInt64] = [:]

    func recordPhase(_ name: String, nanos n: UInt64) {
        lock.lock(); defer { lock.unlock() }
        phases[name, default: 0] += n
    }

    func record(rule: String, nanos n: UInt64, windows w: Int, bytes b: Int) {
        lock.lock(); defer { lock.unlock() }
        nanos[rule, default: 0] += n
        windows[rule, default: 0] += w
        windowBytes[rule, default: 0] += b
    }

    public func report(top: Int = 20) -> String {
        lock.lock(); defer { lock.unlock() }
        let total = nanos.values.reduce(0, +)
        var out = ""
        for (name, n) in phases.sorted(by: { $0.key < $1.key }) { out += String(format: "  phase %-20@ %7.2fs\n", name, Double(n) / 1e9) }
        out += "Per-rule scan time (total \(String(format: "%.2f", Double(total) / 1e9)) s):\n"
        for (rule, n) in nanos.sorted(by: { $0.value > $1.value }).prefix(top) {
            out += String(format: "  %7.2fs  %8d windows  %9.1f MB  %@\n", Double(n) / 1e9, windows[rule] ?? 0, Double(windowBytes[rule] ?? 0) / 1e6, rule)
        }
        return out
    }
}
