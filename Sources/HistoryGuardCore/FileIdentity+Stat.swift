import Foundation

public extension FileIdentity {
    /// Reads device/inode/size/mtime for `url` without following a final symlink component.
    static func read(at url: URL) throws -> FileIdentity {
        var st = stat()
        guard lstat(url.path, &st) == 0 else {
            throw AdapterError.unreadable(url, String(cString: strerror(errno)))
        }
        #if os(Linux)
        let mtime = Date(timeIntervalSince1970: TimeInterval(st.st_mtim.tv_sec) + TimeInterval(st.st_mtim.tv_nsec) / 1e9)
        #else
        let mtime = Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec) + TimeInterval(st.st_mtimespec.tv_nsec) / 1e9)
        #endif
        return FileIdentity(device: UInt64(st.st_dev), inode: UInt64(st.st_ino), size: UInt64(st.st_size), modified: mtime)
    }
}
