import Foundation
import Testing
import HistoryGuardCore
@testable import StoreMonitoring

@Suite struct MonitorStateTests {
    func state(status: MonitorState.Status, verified: Bool) -> MonitorState {
        MonitorState(status: status, secrets: [], occurrences: [], gaps: [], stores: [],
                     lastVerified: verified ? Date() : nil, scanning: false)
    }

    // Before the first reconcile completes, we have not verified anything.
    @Test func emptyIsScanningNotClean() {
        let s = MonitorState.empty
        #expect(!s.isCoverageClean)
        #expect(s.headline == "Scanning supported AI memory…")
    }

    // Clean requires a completed reconcile, no blocking gap, and no inaccessible store.
    @Test func cleanOnlyAfterVerifiedWithNoGapsOrRed() {
        let s = state(status: .green, verified: true)
        #expect(s.isCoverageClean)
        #expect(s.headline == "0 detected secrets in supported AI memory")
    }

    @Test func inaccessibleIsNotClean() {
        let s = state(status: .red, verified: true)
        #expect(!s.isCoverageClean)
        #expect(s.headline != "0 detected secrets in supported AI memory")
    }
}
