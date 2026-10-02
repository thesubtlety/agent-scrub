#if os(macOS)
import Foundation
import Testing
@testable import StoreMonitoring

@Suite struct FSEventsChangeSourceTests {
    @Test func deliversBatchOnFileChange() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let src = FSEventsChangeSource()
        src.start(roots: [dir])
        defer { src.stop() }

        // Let the stream arm, then create a file under the watched root.
        try await Task.sleep(nanoseconds: 400_000_000)
        try Data("x".utf8).write(to: dir.appendingPathComponent("a.txt"))

        // Await the first batch, or time out.
        let got = await withTaskGroup(of: Bool.self) { group -> Bool in
            group.addTask {
                for await _ in src.batches { return true }
                return false
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 6_000_000_000)
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
        }
        #expect(got)
    }
}
#endif
