import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A short-TTL snapshot of running process (executable) names, so adapters can tighten "active session"
/// detection: a store counts as active only if its owning app is actually running, not merely recently written.
/// Best-effort — returns empty off-Darwin or if the process list can't be read.
public enum RunningProcesses {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var cached: (names: Set<String>, at: Date)?

    /// Lowercased executable names of running processes, cached briefly so a reconcile's many calls are cheap.
    public static func names(ttl: TimeInterval = 2) -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        if let c = cached, Date().timeIntervalSince(c.at) < ttl { return c.names }
        let n = snapshot()
        cached = (n, Date())
        return n
    }

    /// True if any running process's name equals or contains `needle` (case-insensitive).
    public static func isRunning(_ needle: String, ttl: TimeInterval = 2) -> Bool {
        let lower = needle.lowercased()
        guard !lower.isEmpty else { return false }
        return names(ttl: ttl).contains { $0 == lower || $0.contains(lower) }
    }

    private static func snapshot() -> Set<String> {
        #if canImport(Darwin)
        let needed = proc_listallpids(nil, 0)   // the sizing call's units vary by SDK, so over-allocate generously
        guard needed > 0 else { return [] }
        let cap = Int(needed) + 1024
        var pids = [pid_t](repeating: 0, count: cap)
        let r = proc_listallpids(&pids, Int32(cap * MemoryLayout<pid_t>.stride))
        guard r > 0 else { return [] }
        var out = Set<String>()
        let bufSize = Int(2 * MAXPATHLEN)
        var buf = [CChar](repeating: 0, count: bufSize)
        for pid in pids where pid > 0 {   // scan the whole buffer; zero entries are just padding
            if proc_name(pid, &buf, UInt32(bufSize)) > 0 {
                out.insert(String(cString: buf).lowercased())
            }
        }
        return out
        #else
        return []
        #endif
    }
}
