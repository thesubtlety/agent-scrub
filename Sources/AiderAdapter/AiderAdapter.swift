import Foundation
import HistoryGuardCore

/// Reads Aider's per-repo history files (`.aider.chat.history.md`, `.aider.input.history`, `.aider.llm.history`).
/// Unlike the other agents, Aider writes these INTO the user's working directory, so discovery is a bounded,
/// denylisted walk of the home directory (and any extra roots) looking for repos that contain them. All three
/// files are plaintext; redaction goes through the shared, verified in-place redactor.
public struct AiderAdapter: AgentAdapter {
    public let id = AiderStores.adapterID
    public let displayName = "Aider"

    /// Extra project roots to search (each walked the same bounded way).
    public var additionalRoots: [URL]
    /// When false, only `additionalRoots` are searched (tests against copied trees).
    public var includeDefaultRoots = true
    /// How deep below a search root to look for repos holding Aider history. Keeps discovery fast and avoids
    /// descending huge trees; combined with `AiderStores.denylistedDirNames`.
    public var maxDepth = 5
    public var maxArtifactBytes: UInt64 = 256 << 20
    /// Files modified more recently than this are treated as possibly-live (see `activeState`).
    public var activityWindow: TimeInterval = 300
    let chunker = TextChunker()
    let walker = JSONStringWalker()

    public init(additionalRoots: [URL] = [], includeDefaultRoots: Bool = true) {
        self.additionalRoots = additionalRoots
        self.includeDefaultRoots = includeDefaultRoots
    }

    // MARK: Discovery

    public func discoverInstallations() async -> [AgentInstallation] {
        let fm = FileManager.default
        var searchRoots: [URL] = []
        if includeDefaultRoots {
            if let env = ProcessInfo.processInfo.environment["AIDER_SEARCH_ROOTS"], !env.isEmpty {
                searchRoots += env.split(separator: ":").map { URL(fileURLWithPath: String($0)) }
            } else {
                searchRoots.append(fm.homeDirectoryForCurrentUser)
            }
        }
        searchRoots += additionalRoots

        var found: [URL] = []
        var seenSearch = Set<String>()
        for root in searchRoots {
            let resolved = root.resolvingSymlinksInPath().standardizedFileURL
            guard seenSearch.insert(resolved.path).inserted else { continue }
            search(resolved, into: &found)
        }

        var seen = Set<String>()
        var out: [AgentInstallation] = []
        for dir in found {
            let resolved = dir.resolvingSymlinksInPath().standardizedFileURL
            guard seen.insert(resolved.path).inserted else { continue }
            out.append(AgentInstallation(adapterID: id, rootURL: resolved, version: nil))
        }
        return out
    }

    /// Iterative, depth-bounded, symlink-free walk. A directory is an installation if it directly contains a
    /// marker file; descent skips hidden and denylisted directories.
    func search(_ root: URL, into found: inout [URL]) {
        let fm = FileManager.default
        var stack: [(URL, Int)] = [(root, 0)]
        while let (dir, depth) = stack.popLast() {
            if AiderStores.markerFiles.contains(where: { fm.fileExists(atPath: dir.appendingPathComponent($0).path) }) {
                found.append(dir)
            }
            guard depth < maxDepth else { continue }
            guard let entries = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: []) else { continue }
            for e in entries {
                let rv = try? e.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                guard rv?.isDirectory == true, rv?.isSymbolicLink != true else { continue }
                let name = e.lastPathComponent
                if name.hasPrefix(".") || AiderStores.denylistedDirNames.contains(name) { continue }
                stack.append((e, depth + 1))
            }
        }
    }

    // MARK: Stores

    public func enumerateStores(installation: AgentInstallation) async throws -> (stores: [StoreDescriptor], gaps: [CoverageGap]) {
        let root = installation.rootURL
        let fm = FileManager.default
        let entries = (try? fm.contentsOfDirectory(atPath: root.path)) ?? []

        var locations: [StoreID: [URL]] = [:]
        var gaps: [CoverageGap] = []
        // Only `.aider.*` entries are ours; everything else in the repo is the user's own project.
        for entry in entries where entry.hasPrefix(".aider.") || entry.hasPrefix(".aider") {
            if let store = AiderStores.store(claiming: entry) {
                locations[store.id, default: []].append(root.appendingPathComponent(entry))
            } else {
                gaps.append(CoverageGap(adapterID: id, storeID: nil,
                                        path: root.appendingPathComponent(entry).path, reason: .unknownStore))
            }
        }

        let stores: [StoreDescriptor] = AiderStores.known.map { k in
            let locs = locations[k.id] ?? []
            return StoreDescriptor(
                id: k.id, adapterID: id, displayName: k.name, locations: locs, tier: k.tier,
                capabilities: k.tier == .excluded ? [] : [.detect, .verify, .redactWhenInactive],
                schema: .known(version: AiderStores.schemaVersion), present: !locs.isEmpty,
                exclusionReason: k.exclusionReason)
        }
        return (stores, gaps)
    }

    // MARK: Artifacts

    public func enumerateArtifacts(store: StoreDescriptor, cursor: ScanCursor?) async throws -> ArtifactPage {
        var artifacts: [Artifact] = []
        var gaps: [CoverageGap] = []
        for location in store.locations {
            let rv = try location.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if rv.isSymbolicLink == true {
                gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: location.path,
                                        reason: .skippedSymlink(target: (try? FileManager.default.destinationOfSymbolicLink(atPath: location.path)) ?? "?")))
                continue
            }
            if rv.isDirectory == true { continue }   // the known history entries are files, not dirs
            let identity = try FileIdentity.read(at: location)
            if identity.size > maxArtifactBytes {
                gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: location.path,
                                        reason: .oversizeArtifact(bytes: identity.size, limit: maxArtifactBytes)))
                continue
            }
            let kind: ArtifactKind = isBinary(location) ? .binary : .plainText
            artifacts.append(Artifact(url: location, storeID: store.id, kind: kind, identity: identity,
                                      sessionID: nil, projectPath: location.deletingLastPathComponent().lastPathComponent))
        }
        return ArtifactPage(artifacts: artifacts, gaps: gaps)
    }

    func isBinary(_ url: URL) -> Bool {
        guard let fh = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? fh.close() }
        guard let head = try? fh.read(upToCount: 8192) else { return false }
        return head.contains(0)
    }

    // MARK: Content extraction

    public func extractScannableContent(artifact: Artifact) async throws -> ExtractedContent {
        switch artifact.kind {
        case .binary:
            return ExtractedContent(regions: [], gaps: [CoverageGap(adapterID: id, storeID: artifact.storeID,
                                                                    path: artifact.url.path, reason: .binaryArtifact)],
                                    bytesExamined: 0)
        case .sqlite:
            throw AdapterError.notSupported("Aider has no SQLite stores")
        case .json, .jsonl, .plainText:
            return try extractPlainText(artifact)   // .md and the .history files are all plain text
        }
    }

    func extractPlainText(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        let bytes = try chunker.forEachChunk(at: artifact.url) { chunk in
            regions.append(rawRegion(chunk.bytes, offset: chunk.offset, locator: .plainFile))
        }
        return ExtractedContent(regions: regions, gaps: [], bytesExamined: UInt64(bytes))
    }

    func rawRegion(_ bytes: [UInt8], offset: Int, locator: RecordLocator) -> ContentRegion {
        let text = String(decoding: bytes, as: UTF8.self)
        return ContentRegion(text: text, locator: locator, baseOffset: offset, offsetMap: nil,
                             hasEscapes: false, offsetsReliable: text.utf8.count == bytes.count)
    }

    // MARK: Activity

    public func activeState(artifact: Artifact) async -> ArtifactActivity {
        // Aider gives no per-session process signal, so be conservative: a very recently written file may be
        // mid-append by a live aider. Treat recent writes as active; byte-preserving redaction can still be
        // forced via "include active sessions" (a resize is always deferred on an active file regardless).
        let age = Date().timeIntervalSince(artifact.identity.modified)
        return age < activityWindow
            ? .active(reason: "modified \(Int(age))s ago (Aider has no session marker; treated as possibly live)")
            : .inactive
    }

    // MARK: Mutation

    public func redactionConstraint(for occurrence: SecretOccurrence, in store: StoreDescriptor) -> RedactionDeferral? {
        store.tier == .excluded ? .storeReadOnly : nil
    }

    public func apply(plan: RedactionPlan, verifyPreimage: @Sendable @escaping ([UInt8], RedactionTarget) -> Bool) async throws -> RedactionResult {
        RedactionResult(outcomes: InPlaceRedactor(maxRecordBytes: 64 << 20).apply(targets: plan.targets, verifyPreimage: verifyPreimage))
    }
}
