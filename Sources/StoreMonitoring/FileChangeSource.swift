import Foundation

/// A debounced, stability-checked batch of filesystem changes under the watched roots.
public struct FileChangeBatch: Sendable {
    public let changedPaths: [URL]
    /// FSEvents reported dropped events (kFSEventStreamEventFlagMustScanSubDirs): reconcile broadly.
    public let dropped: Bool
    /// A watched root was created, removed, or replaced.
    public let rootChanged: Bool
    public init(changedPaths: [URL], dropped: Bool = false, rootChanged: Bool = false) {
        self.changedPaths = changedPaths; self.dropped = dropped; self.rootChanged = rootChanged
    }
}

public protocol FileChangeSource: AnyObject, Sendable {
    var batches: AsyncStream<FileChangeBatch> { get }
    func start(roots: [URL])
    func stop()
}

/// Test/driver source: the caller pushes batches explicitly.
public final class ManualChangeSource: FileChangeSource, @unchecked Sendable {
    public let batches: AsyncStream<FileChangeBatch>
    private let cont: AsyncStream<FileChangeBatch>.Continuation
    public init() {
        var c: AsyncStream<FileChangeBatch>.Continuation!
        batches = AsyncStream { c = $0 }
        cont = c
    }
    public func start(roots: [URL]) {}
    public func stop() { cont.finish() }
    public func push(_ batch: FileChangeBatch) { cont.yield(batch) }
}
