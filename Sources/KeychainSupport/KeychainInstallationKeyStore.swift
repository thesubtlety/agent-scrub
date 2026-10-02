#if os(macOS)
import Foundation
import Security
import HistoryGuardCore

/// Stores the 256-bit HMAC installation key in the macOS Keychain as a generic-password item.
/// This is the shipping key store; it replaces the 0600 file used for Linux/dev.
public struct KeychainInstallationKeyStore: InstallationKeyStore {
    public enum KeychainError: Error { case status(OSStatus), badData }
    let service: String
    let account: String
    public init(service: String = "io.adversis.history-guard", account: String = "installation-key") {
        self.service = service; self.account = account
    }

    public func loadOrCreate() throws -> InstallationKey {
        if let data = try read(), data.count == 32 { return InstallationKey(data: data) }
        let key = InstallationKey.random()
        try add(key.data)
        return key
    }

    private func baseQuery() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private func read() throws -> Data? {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        guard let data = out as? Data else { throw KeychainError.badData }
        return data
    }

    private func add(_ data: Data) throws {
        var q = baseQuery()
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    /// Test-only cleanup.
    func deleteForTesting() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }
}
#endif
