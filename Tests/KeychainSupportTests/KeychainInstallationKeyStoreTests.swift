#if os(macOS)
import Foundation
import Testing
import HistoryGuardCore
@testable import KeychainSupport

@Suite struct KeychainInstallationKeyStoreTests {
    @Test func loadOrCreateIsStable() throws {
        // Unique service so the test never touches the real installation key.
        let service = "io.adversis.history-guard.test." + UUID().uuidString
        let store = KeychainInstallationKeyStore(service: service, account: "installation-key")
        defer { try? store.deleteForTesting() }
        let a = try store.loadOrCreate()
        let b = try store.loadOrCreate()
        #expect(a.data == b.data)        // same key on the second call
        #expect(a.data.count == 32)
    }
}
#endif
