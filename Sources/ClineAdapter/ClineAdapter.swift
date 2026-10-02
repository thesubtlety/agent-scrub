import Foundation
import HistoryGuardCore

/// Reads Cline (the `saoudrizwan.claude-dev` VS Code extension) history. Supports the legacy globalStorage
/// layout (`tasks/<id>/api_conversation_history.json` + `ui_messages.json`, `state/taskHistory.json`,
/// `checkpoints/`) and the newer SDK-era `~/.cline/data/sessions/<id>/*.json`. Config is enumerated but never
/// scanned. All content is JSON, redacted in place through the shared engine.
public struct ClineAdapter: AgentAdapter {
    public let id = ClineStores.adapterID
    public let displayName = "Cline"

    /// Extra roots the user added (a saoudrizwan.claude-dev dir, or an alternate ~/.cline).
    public var additionalRoots: [URL]
    /// When false, only `additionalRoots` are considered (tests against copied trees).
    public var includeDefaultRoots = true
    public var maxArtifactBytes: UInt64 = 256 << 20
    /// Files modified more recently than this are treated as possibly-live (see `activeState`).
    public var activityWindow: TimeInterval = 300
    let chunker = TextChunker()
    let walker = JSONStringWalker()
    let jsonl = JSONLReader()

    /// VS Code variants whose globalStorage can hold the Cline extension.
    static let editors = ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"]

    public init(additionalRoots: [URL] = [], includeDefaultRoots: Bool = true) {
        self.additionalRoots = additionalRoots
        self.includeDefaultRoots = includeDefaultRoots
    }

    // MARK: Discovery

    public func discoverInstallations() async -> [AgentInstallation] {
        let fm = FileManager.default
        var candidates: [URL] = []
        if includeDefaultRoots {
            if let env = ProcessInfo.processInfo.environment["CLINE_DIR"], !env.isEmpty {
                candidates.append(URL(fileURLWithPath: env))
            }
            let appSupport = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
            for editor in Self.editors {
                candidates.append(appSupport.appendingPathComponent("\(editor)/User/globalStorage/saoudrizwan.claude-dev"))
            }
            candidates.append(fm.homeDirectoryForCurrentUser.appendingPathComponent(".cline"))
        }
        candidates.append(contentsOf: additionalRoots)

        var seen = Set<String>()
        var out: [AgentInstallation] = []
        for c in candidates {
            let resolved = c.resolvingSymlinksInPath().standardizedFileURL
            guard seen.insert(resolved.path).inserted else { continue }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: resolved.path, isDirectory: &isDir), isDir.boolValue else { continue }
            out.append(AgentInstallation(adapterID: id, rootURL: resolved, version: nil))
        }
        return out
    }

    // MARK: Stores

    public func enumerateStores(installation: AgentInstallation) async throws -> (stores: [StoreDescriptor], gaps: [CoverageGap]) {
        let root = installation.rootURL
        let fm = FileManager.default
        let entries = try fm.contentsOfDirectory(atPath: root.path)

        var locations: [StoreID: [URL]] = [:]
        var gaps: [CoverageGap] = []
        for entry in entries where !ClineStores.ignorableRootEntries.contains(entry) {
            if let store = ClineStores.store(claiming: entry) {
                locations[store.id, default: []].append(root.appendingPathComponent(entry))
            } else {
                gaps.append(CoverageGap(adapterID: id, storeID: nil, path: root.appendingPathComponent(entry).path,
                                        reason: .unknownStore))
            }
        }
        // `tasks/` feeds both conversations and ui-messages.
        if let tasks = locations[ClineStores.conversations] {
            locations[ClineStores.uiMessages, default: []] += tasks
        }

        let stores: [StoreDescriptor] = ClineStores.known.map { k in
            let locs = locations[k.id] ?? []
            return StoreDescriptor(
                id: k.id, adapterID: id, displayName: k.name, locations: locs, tier: k.tier,
                capabilities: k.tier == .excluded ? [] : [.detect, .verify, .redactWhenInactive],
                schema: .known(version: ClineStores.schemaVersion), present: !locs.isEmpty,
                exclusionReason: k.exclusionReason)
        }
        return (stores, gaps)
    }

    // MARK: Artifacts

    public func enumerateArtifacts(store: StoreDescriptor, cursor: ScanCursor?) async throws -> ArtifactPage {
        var artifacts: [Artifact] = []
        var gaps: [CoverageGap] = []
        let fm = FileManager.default

        for location in store.locations {
            let rv = try location.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if rv.isSymbolicLink == true {
                gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: location.path,
                                        reason: .skippedSymlink(target: (try? fm.destinationOfSymbolicLink(atPath: location.path)) ?? "?")))
                continue
            }
            if rv.isDirectory != true {
                try classify(file: location, store: store, relativeTo: location.deletingLastPathComponent(), into: &artifacts, gaps: &gaps)
                continue
            }
            let dirName = location.lastPathComponent   // "tasks", "data", "state", "checkpoints"
            guard let e = fm.enumerator(at: location, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
                                        options: []) else { continue }
            while let url = e.nextObject() as? URL {
                let v = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if v.isSymbolicLink == true {
                    e.skipDescendants()
                    gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path,
                                            reason: .skippedSymlink(target: (try? fm.destinationOfSymbolicLink(atPath: url.path)) ?? "?")))
                    continue
                }
                if v.isDirectory == true { continue }
                if let owner = ownerStore(forDir: dirName, url: url, under: location) {
                    if owner == nil {
                        // Unknown file inside a shared dir — report once from the primary store.
                        if store.id == primaryStore(forDir: dirName) {
                            gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path, reason: .unknownStore))
                        }
                        continue
                    }
                    guard owner == store.id else { continue }
                }
                try classify(file: url, store: store, relativeTo: location, into: &artifacts, gaps: &gaps)
            }
        }
        return ArtifactPage(artifacts: artifacts, gaps: gaps)
    }

    /// For a shared/structured directory, which store owns `url` (Optional<StoreID>? — outer nil means this dir
    /// isn't split, scan everything; inner nil means an unrecognised file inside a split dir).
    private func ownerStore(forDir dirName: String, url: URL, under location: URL) -> StoreID?? {
        switch dirName {
        case "tasks": return .some(ClineStores.classifyTasksFile(relativeComponents: relativeComponents(of: url, under: location)))
        case "data":  return .some(ClineStores.classifyDataFile(relativeComponents: relativeComponents(of: url, under: location)))
        default:      return nil   // state / checkpoints: single-store dir, no per-file split
        }
    }

    private func primaryStore(forDir dirName: String) -> StoreID {
        dirName == "data" ? ClineStores.sessions : ClineStores.conversations
    }

    func relativeComponents(of url: URL, under base: URL) -> [String] {
        let b = base.standardizedFileURL.pathComponents
        let u = url.standardizedFileURL.pathComponents
        guard u.count >= b.count else { return [] }
        return Array(u[b.count...])
    }

    func classify(file url: URL, store: StoreDescriptor, relativeTo base: URL, into artifacts: inout [Artifact], gaps: inout [CoverageGap]) throws {
        let identity = try FileIdentity.read(at: url)
        if identity.size > maxArtifactBytes {
            gaps.append(CoverageGap(adapterID: id, storeID: store.id, path: url.path,
                                    reason: .oversizeArtifact(bytes: identity.size, limit: maxArtifactBytes)))
            return
        }
        let name = url.lastPathComponent
        let kind: ArtifactKind
        if name.contains(".jsonl") { kind = .jsonl }
        else if url.pathExtension == "json" { kind = .json }
        else if isBinary(url) { kind = .binary }
        else { kind = .plainText }

        artifacts.append(Artifact(url: url, storeID: store.id, kind: kind, identity: identity,
                                  sessionID: nil, projectPath: nil))
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
            throw AdapterError.notSupported("Cline has no SQLite stores")
        case .jsonl:
            return try extractJSONL(artifact)
        case .json:
            return try extractJSON(artifact)
        case .plainText:
            return try extractPlainText(artifact)
        }
    }

    func extractJSONL(_ artifact: Artifact) throws -> ExtractedContent {
        var regions: [ContentRegion] = []
        var gaps: [CoverageGap] = []
        let summary = try jsonl.forEachLine(at: artifact.url) { line in
            if line.bytes.isEmpty { return }
            do {
                for s in try walker.strings(in: line.bytes) {
                    regions.append(ContentRegion(
                        text: s.text,
                        locator: .jsonlRecord(line: line.index, lineOffset: line.offset, pointer: s.pointer),
                        baseOffset: line.offset + s.bodyRange.lowerBound,
                        offsetMap: s.offsetMap.map { $0.map { $0 + line.offset } },
                        hasEscapes: s.hasEscapes))
                }
            } catch {
                let reason: CoverageGap.Reason = line.isTruncatedTail
                    ? .truncatedTail(line: line.index)
                    : .corruptRecord(line: line.index, detail: String(describing: error))
                gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path, reason: reason))
                regions.append(rawRegion(line.bytes, offset: line.offset,
                                         locator: .jsonlRecord(line: line.index, lineOffset: line.offset, pointer: "")))
            }
        }
        for skipped in summary.skippedOversize {
            gaps.append(CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                    reason: .oversizeRecord(line: skipped.line, offset: skipped.offset, limit: jsonl.maxRecordBytes)))
        }
        return ExtractedContent(regions: regions, gaps: gaps, bytesExamined: UInt64(summary.bytesRead))
    }

    func extractJSON(_ artifact: Artifact) throws -> ExtractedContent {
        let data = try Data(contentsOf: artifact.url)
        do {
            let regions = try walker.strings(in: data).map { s in
                ContentRegion(text: s.text, locator: .jsonDocument(pointer: s.pointer), baseOffset: s.bodyRange.lowerBound,
                              offsetMap: s.offsetMap, hasEscapes: s.hasEscapes)
            }
            return ExtractedContent(regions: regions, gaps: [], bytesExamined: UInt64(data.count))
        } catch {
            let gap = CoverageGap(adapterID: id, storeID: artifact.storeID, path: artifact.url.path,
                                  reason: .corruptRecord(line: 0, detail: String(describing: error)))
            return ExtractedContent(regions: [rawRegion(Array(data), offset: 0, locator: .plainFile)],
                                    gaps: [gap], bytesExamined: UInt64(data.count))
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
        // Cline writes no per-session PID marker we can read. Be conservative for redaction safety: treat a very
        // recently modified file as possibly mid-write by a live session. The user can still force redaction
        // ("include active sessions"); a resize is always deferred on an active file regardless.
        let age = Date().timeIntervalSince(artifact.identity.modified)
        return age < activityWindow
            ? .active(reason: "modified \(Int(age))s ago (Cline has no session marker; treated as possibly live)")
            : .inactive
    }

    // MARK: Mutation

    public func redactionConstraint(for occurrence: SecretOccurrence, in store: StoreDescriptor) -> RedactionDeferral? {
        store.tier == .excluded ? .storeReadOnly : nil
    }

    public func apply(plan: RedactionPlan, verifyPreimage: @Sendable @escaping ([UInt8], RedactionTarget) -> Bool) async throws -> RedactionResult {
        RedactionResult(outcomes: InPlaceRedactor(maxRecordBytes: jsonl.maxRecordBytes).apply(targets: plan.targets, verifyPreimage: verifyPreimage))
    }
}
