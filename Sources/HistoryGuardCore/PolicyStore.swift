import Foundation

public struct PolicyRecord: Codable, Sendable, Hashable {
    public var policy: RetentionPolicy
    public var label: String
    public var createdAt: Date
    public init(policy: RetentionPolicy, label: String, createdAt: Date = Date()) {
        self.policy = policy
        self.label = label
        self.createdAt = createdAt
    }
}

/// Retention policies keyed by secret fingerprint. Contains labels and fingerprints only, never plaintext.
public protocol PolicyStore: Sendable {
    func all() throws -> [SecretFingerprint: PolicyRecord]
    func set(_ record: PolicyRecord, for fingerprint: SecretFingerprint) throws
    func remove(_ fingerprint: SecretFingerprint) throws
}

public extension PolicyStore {
    func policy(for fingerprint: SecretFingerprint) -> RetentionPolicy? {
        (try? all())?[fingerprint]?.policy
    }
}

/// JSON file store. macOS builds may later move this into the app's SQLite index; the shape is the same.
public struct FilePolicyStore: PolicyStore {
    public let url: URL
    public init(url: URL) { self.url = url }

    public static func defaultLocation() -> URL {
        FileInstallationKeyStore.defaultLocation().deletingLastPathComponent().appendingPathComponent("policies.json")
    }

    struct FileShape: Codable { var version: Int; var policies: [String: PolicyRecord] }

    func load() throws -> FileShape {
        guard let data = try? Data(contentsOf: url) else { return FileShape(version: 1, policies: [:]) }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return try dec.decode(FileShape.self, from: data)
    }

    func save(_ shape: FileShape) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]; enc.dateEncodingStrategy = .iso8601
        try enc.encode(shape).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public func all() throws -> [SecretFingerprint: PolicyRecord] {
        var out: [SecretFingerprint: PolicyRecord] = [:]
        for (hex, rec) in try load().policies {
            guard hex.count == 64, let data = Data(hexString: hex) else { continue }
            out[SecretFingerprint(bytes: data)] = rec
        }
        return out
    }

    public func set(_ record: PolicyRecord, for fingerprint: SecretFingerprint) throws {
        var shape = try load()
        shape.policies[fingerprint.hex] = record
        try save(shape)
    }

    public func remove(_ fingerprint: SecretFingerprint) throws {
        var shape = try load()
        shape.policies[fingerprint.hex] = nil
        try save(shape)
    }
}

public extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var out = Data(capacity: hexString.count / 2)
        var idx = hexString.startIndex
        while idx < hexString.endIndex {
            let next = hexString.index(idx, offsetBy: 2)
            guard let b = UInt8(hexString[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        self = out
    }
}
