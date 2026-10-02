#if os(macOS)
import Foundation
import CoreServices

/// Watches root trees with an FSEventStream and emits debounced, stability-checked change batches.
/// Runs on its own serial dispatch queue; never touches the UI thread.
public final class FSEventsChangeSource: FileChangeSource, @unchecked Sendable {
    public let batches: AsyncStream<FileChangeBatch>
    private let cont: AsyncStream<FileChangeBatch>.Continuation
    private let queue = DispatchQueue(label: "io.adversis.history-guard.fsevents")
    private var stream: FSEventStreamRef?
    private var pending: Set<String> = []
    private var dropped = false
    private var rootChanged = false
    private var debounce: DispatchWorkItem?

    public init() {
        var c: AsyncStream<FileChangeBatch>.Continuation!
        batches = AsyncStream { c = $0 }
        cont = c
    }

    public func start(roots: [URL]) {
        queue.async { self._start(roots: roots) }
    }

    private func _start(roots: [URL]) {
        guard !roots.isEmpty else { return }
        let paths = roots.map { $0.path } as CFArray
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer
                           | kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagUseCFTypes)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, eventFlags, _ in
            guard let info else { return }
            let me = Unmanaged<FSEventsChangeSource>.fromOpaque(info).takeUnretainedValue()
            let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] ?? []
            var drop = false, rootChg = false
            for i in 0..<count {
                let f = eventFlags[i]
                if f & FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs) != 0 { drop = true }
                if f & FSEventStreamEventFlags(kFSEventStreamEventFlagRootChanged) != 0 { rootChg = true }
            }
            me.enqueue(paths: paths, dropped: drop, rootChanged: rootChg)
        }
        guard let s = FSEventStreamCreate(kCFAllocatorDefault, callback, &context, paths,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                          0.25, flags) else { return }
        stream = s
        FSEventStreamSetDispatchQueue(s, queue)
        FSEventStreamStart(s)
    }

    private func enqueue(paths: [String], dropped: Bool, rootChanged: Bool) {
        // Already on `queue` (the stream's dispatch queue).
        pending.formUnion(paths)
        self.dropped = self.dropped || dropped
        self.rootChanged = self.rootChanged || rootChanged
        debounce?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.flush() }
        debounce = work
        queue.asyncAfter(deadline: .now() + 1.0, execute: work)   // ~1s stability window
    }

    private func flush() {
        let batch = FileChangeBatch(changedPaths: pending.map { URL(fileURLWithPath: $0) },
                                    dropped: dropped, rootChanged: rootChanged)
        pending.removeAll(); dropped = false; rootChanged = false
        cont.yield(batch)
    }

    public func stop() {
        queue.async {
            if let s = self.stream {
                FSEventStreamStop(s); FSEventStreamInvalidate(s); FSEventStreamRelease(s); self.stream = nil
            }
            self.cont.finish()
        }
    }
}
#endif
