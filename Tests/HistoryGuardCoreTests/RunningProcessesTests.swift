import Foundation
import Testing
@testable import HistoryGuardCore

@Suite struct RunningProcessesTests {
    @Test func listsRunningProcessesOnDarwin() {
        let names = RunningProcesses.names()
        #if canImport(Darwin)
        #expect(!names.isEmpty)   // at minimum this test's own process is listed
        #expect(!RunningProcesses.isRunning("definitely-not-a-real-process-xyz-123"))
        #else
        #expect(names.isEmpty)
        #endif
    }
}
