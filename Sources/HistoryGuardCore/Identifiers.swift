import Foundation

/// Stable identifier for a supported agent (e.g. "claude-code", "codex").
public struct AdapterID: RawRepresentable, Hashable, Codable, Sendable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(_ raw: String) { self.rawValue = raw }
    public var description: String { rawValue }
}

/// Stable identifier for a persistence store within an adapter (e.g. "prompt-history").
public struct StoreID: RawRepresentable, Hashable, Codable, Sendable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(_ raw: String) { self.rawValue = raw }
    public var description: String { rawValue }
}

/// Filesystem identity that survives renames. `nil` fields are unknown on this platform.
public struct FileIdentity: Hashable, Codable, Sendable {
    public var device: UInt64?
    public var inode: UInt64?
    public var size: UInt64
    public var modified: Date

    public init(device: UInt64?, inode: UInt64?, size: UInt64, modified: Date) {
        self.device = device
        self.inode = inode
        self.size = size
        self.modified = modified
    }
}
