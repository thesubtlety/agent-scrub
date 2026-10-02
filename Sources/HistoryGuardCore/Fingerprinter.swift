import Crypto
import Foundation

/// 256-bit per-installation key. On macOS this lives in the Keychain; the file store below is for
/// Linux development and tests only.
public struct InstallationKey: Sendable {
    public let data: Data
    public init(data: Data) {
        precondition(data.count == 32, "installation key must be 32 bytes")
        self.data = data
    }
    var symmetricKey: SymmetricKey { SymmetricKey(data: data) }
    public static func random() -> InstallationKey {
        var d = Data(count: 32)
        d.withUnsafeMutableBytes { buf in
            for i in buf.indices { buf[i] = UInt8.random(in: .min ... .max) }
        }
        return InstallationKey(data: d)
    }
}

public protocol InstallationKeyStore: Sendable {
    func loadOrCreate() throws -> InstallationKey
}

public struct InMemoryKeyStore: InstallationKeyStore {
    let key: InstallationKey
    public init(key: InstallationKey) { self.key = key }
    public func loadOrCreate() throws -> InstallationKey { key }
}

/// Stores the key in a 0600 file. Development/Linux only; never ship this on macOS.
public struct FileInstallationKeyStore: InstallationKeyStore {
    public let url: URL
    public init(url: URL) { self.url = url }

    public static func defaultLocation() -> URL {
        let env = ProcessInfo.processInfo.environment
        let base = env["XDG_DATA_HOME"].map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share")
        return base.appendingPathComponent("history-guard/installation.key")
    }

    public func loadOrCreate() throws -> InstallationKey {
        let fm = FileManager.default
        if let data = try? Data(contentsOf: url), data.count == 32 {
            return InstallationKey(data: data)
        }
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let key = InstallationKey.random()
        try key.data.write(to: url, options: [.atomic])
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return key
    }
}

/// fingerprint = HMAC-SHA256(installationKey, detectorNamespace || 0x00 || canonicalSecretBytes)
public struct Fingerprinter: Sendable {
    let key: InstallationKey
    public init(key: InstallationKey) { self.key = key }

    public func fingerprint(namespace: String, canonical: Data) -> SecretFingerprint {
        var hmac = HMAC<SHA256>(key: key.symmetricKey)
        hmac.update(data: Data(namespace.utf8))
        hmac.update(data: Data([0x00]))
        hmac.update(data: canonical)
        return SecretFingerprint(bytes: Data(hmac.finalize()))
    }
}
