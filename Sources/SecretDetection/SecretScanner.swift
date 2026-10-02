import Foundation
import HistoryGuardCore

/// A detector hit inside one piece of text. `range` is in UTF-8 byte offsets relative to the scanned text.
public struct SecretMatch: Sendable {
    public let ruleID: String
    public let kind: SecretKind
    public let label: String
    public let confidence: Confidence
    public let range: Range<Int>
    public let canonical: Data
    public let namespace: String
    public let maskedDisplay: String
    /// The plaintext. Present only in memory during a scan; must never be persisted or logged.
    public let plaintext: String
}

/// `Regex` is not formally Sendable but is immutable and safe to share once constructed.
public struct SecretScanner: @unchecked Sendable {
    public let catalog: RuleCatalog
    /// Characters of surrounding context inspected for required/excluded context patterns.
    public var contextWindow = 160
    let anchorIndex: AnchorIndex
    let nearChecks: [AnchorIndex.NearCheck?]

    public init(catalog: RuleCatalog) {
        self.catalog = catalog
        anchorIndex = AnchorIndex(anchorsByRule: catalog.rules.map(\.anchors))
        nearChecks = catalog.rules.map { rule in
            guard let near = rule.requireNear else { return nil }
            var table = [Bool](repeating: false, count: 256)
            for b in near.chars.utf8 { table[Int(b)] = true }
            return AnchorIndex.NearCheck(chars: table, within: near.within)
        }
    }

    public func scan(_ text: String) -> [SecretMatch] {
        var hits: [SecretMatch] = []
        // ASCII-only lowercase keeps byte offsets identical to `text`; anchors are ASCII.
        let profiling = ScanProfile.shared.enabled
        let tStart = profiling ? DispatchTime.now().uptimeNanoseconds : 0
        let lower: [UInt8] = text.utf8.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 0x20 : $0 }
        let anchorHits = anchorIndex.hits(in: lower, near: nearChecks)
        if profiling { ScanProfile.shared.recordPhase("lowercase+anchors", nanos: DispatchTime.now().uptimeNanoseconds - tStart) }
        defer { if profiling { ScanProfile.shared.recordPhase("scan() total", nanos: DispatchTime.now().uptimeNanoseconds - tStart) } }
        for ruleIndex in 0..<catalog.rules.count {
            let rule = catalog.rules[ruleIndex]
            let windows: [Range<String.Index>]
            let regex: Regex<AnyRegexOutput>
            if rule.anchors.isEmpty {
                windows = [text.startIndex..<text.endIndex]
                regex = rule.regex
            } else {
                let starts = anchorHits[ruleIndex]
                if starts.isEmpty { continue }
                if let anchored = rule.anchoredRegex {
                    // One attempt per hit: the window starts at the keyword and the regex is anchored with ^.
                    regex = anchored
                    let u = text.utf8
                    windows = starts.map { start in
                        u.index(u.startIndex, offsetBy: start)..<u.index(u.startIndex, offsetBy: min(lower.count, start + rule.window.after))
                    }
                } else {
                    regex = rule.regex
                    windows = anchorWindows(rule: rule, anchorStarts: starts, lower: lower, text: text)
                }
                if windows.isEmpty { continue }
            }
            var seenStarts = Set<String.Index>()
            let allowlists = rule.allowlists + catalog.globalAllowlists
            let t0 = profiling ? DispatchTime.now().uptimeNanoseconds : 0
            defer {
                if profiling {
                    let bytes = windows.reduce(0) { $0 + text.utf8.distance(from: $1.lowerBound, to: $1.upperBound) }
                    ScanProfile.shared.record(rule: rule.id, nanos: DispatchTime.now().uptimeNanoseconds - t0, windows: windows.count, bytes: bytes)
                }
            }
            for window in windows {
                for m in text[window].matches(of: regex) {
                    let rawRange = secretRange(in: m, rule: rule)
                    guard seenStarts.insert(rawRange.lowerBound).inserted else { continue }
                    let trimmed = rule.canonicalizer.trimmedMatch(text[rawRange])
                    guard !trimmed.isEmpty else { continue }
                    let secretRange = trimmed.startIndex..<trimmed.endIndex
                    let secret = String(trimmed)
                    if isPlaceholder(secret) { continue }
                    if let minEntropy = rule.minEntropy, shannonEntropy(secret) <= minEntropy { continue }
                    if let validator = rule.validator, !Validators.validate(validator, secret: secret) { continue }
                    if !contextAllows(rule: rule, text: text, around: m.range) { continue }
                    if !allowlists.isEmpty {
                        let line = lineContaining(m.range, in: text)
                        if allowlists.contains(where: { $0.allows(secret: secret, match: text[m.range], line: line) }) { continue }
                    }

                    var confidence = rule.confidence
                    if rule.isKeyed {
                        guard let c = keyedConfidence(secret) else { continue }
                        confidence = c
                    }
                    let lo = text.utf8.distance(from: text.startIndex, to: secretRange.lowerBound)
                    let hi = text.utf8.distance(from: text.startIndex, to: secretRange.upperBound)
                    hits.append(SecretMatch(
                        ruleID: rule.id,
                        kind: rule.kind,
                        label: rule.label,
                        confidence: confidence,
                        range: lo..<hi,
                        canonical: rule.canonicalizer.canonicalize(secret),
                        namespace: rule.namespace,
                        maskedDisplay: Masker.mask(secret, kind: rule.kind, spec: rule.mask),
                        plaintext: secret
                    ))
                }
            }
        }
        return resolveOverlaps(hits)
    }

    /// gitleaks semantics: explicit `secretGroup`, else a group named "secret", else the first non-empty
    /// capture group, else the whole match.
    func secretRange(in m: Regex<AnyRegexOutput>.Match, rule: SecretRule) -> Range<String.Index> {
        if let g = rule.secretGroup, g > 0, g < m.output.count, let r = m.output[g].range { return r }
        if let r = m["secret"]?.range { return r }
        for element in m.output.dropFirst() {
            if let r = element.range, !r.isEmpty { return r }
        }
        return m.range
    }

    func lineContaining(_ r: Range<String.Index>, in text: String) -> Substring {
        var start = r.lowerBound
        while start > text.startIndex {
            let prev = text.index(before: start)
            if text[prev].isNewline { break }
            start = prev
        }
        var end = r.upperBound
        while end < text.endIndex, !text[end].isNewline { end = text.index(after: end) }
        return text[start..<end]
    }

    /// Merged byte windows around every anchor occurrence, converted to string indices.
    func anchorWindows(rule: SecretRule, anchorStarts: [Int], lower: [UInt8], text: String) -> [Range<String.Index>] {
        var byteRanges: [Range<Int>] = []
        byteRanges.reserveCapacity(anchorStarts.count)
        for start in anchorStarts {
            byteRanges.append(max(0, start - rule.window.before)..<min(lower.count, start + rule.window.after))
        }
        if byteRanges.isEmpty { return [] }
        byteRanges.sort { $0.lowerBound < $1.lowerBound }
        var merged: [Range<Int>] = [byteRanges[0]]
        for r in byteRanges.dropFirst() {
            if r.lowerBound <= merged[merged.count - 1].upperBound {
                let m = merged[merged.count - 1]
                merged[merged.count - 1] = m.lowerBound..<max(m.upperBound, r.upperBound)
            } else {
                merged.append(r)
            }
        }
        let u = text.utf8
        return merged.map { r in
            // Subscripting rounds down to a scalar boundary, so a mid-character byte offset is safe.
            u.index(u.startIndex, offsetBy: r.lowerBound)..<u.index(u.startIndex, offsetBy: r.upperBound)
        }
    }

    /// A value is a placeholder only when a placeholder pattern DOMINATES it — the matched span covers at least
    /// half the value. Otherwise a real high-entropy secret that merely contains a common word (the canonical AWS
    /// example key ends in "EXAMPLEKEY", API keys can embed "test"/"your") would be silently discarded. Anchored
    /// placeholders (`^…$`) still match the whole value and reject it as before.
    func isPlaceholder(_ s: String) -> Bool {
        guard !s.isEmpty else { return true }
        for p in catalog.placeholders {
            guard let m = try? p.firstMatch(in: s) else { continue }
            if s[m.range].count * 2 >= s.count { return true }
        }
        return false
    }

    func contextAllows(rule: SecretRule, text: String, around r: Range<String.Index>) -> Bool {
        if rule.requiredContext.isEmpty && rule.excludedContext.isEmpty { return true }
        let start = text.index(r.lowerBound, offsetBy: -contextWindow, limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(r.upperBound, offsetBy: contextWindow, limitedBy: text.endIndex) ?? text.endIndex
        let window = text[start..<end]
        if !rule.requiredContext.isEmpty, !rule.requiredContext.contains(where: { window.contains($0) }) { return false }
        if rule.excludedContext.contains(where: { window.contains($0) }) { return false }
        return true
    }

    /// Layer B/C: a keyed value is reported only if it looks like a credential rather than a word.
    /// Entropy never creates a finding on its own; here it only grades one that already has key-name evidence.
    func keyedConfidence(_ s: String) -> Confidence? {
        let n = s.count
        if n < 8 { return nil }
        let h = shannonEntropy(s)
        let classes = characterClasses(s)
        if s.allSatisfy(\.isLetter), n < 20 { return nil }             // a plain word
        if !s.contains(where: \.isNumber), s.contains(dottedIdentifier) { return nil } // req.headers.authorization
        if h < 2.5 { return nil }                                       // "aaaabbbb", "12341234"
        if n >= 16, h >= 3.5, classes >= 3 { return .medium }
        if n >= 12, h >= 3.0, classes >= 2 { return .low }
        return nil
    }

    let dottedIdentifier = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/

    func shannonEntropy(_ s: String) -> Double {
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return counts.values.reduce(0.0) { acc, c in
            let p = Double(c) / n
            return acc - p * log2(p)
        }
    }

    func characterClasses(_ s: String) -> Int {
        var lower = false, upper = false, digit = false, other = false
        for c in s {
            if c.isLowercase { lower = true } else if c.isUppercase { upper = true }
            else if c.isNumber { digit = true } else { other = true }
        }
        return [lower, upper, digit, other].filter { $0 }.count
    }

    /// When two matches overlap, keep the more specific one: higher confidence, then kind specificity, then longer. Fully deterministic.
    func resolveOverlaps(_ hits: [SecretMatch]) -> [SecretMatch] {
        let sorted = hits.sorted { a, b in
            if a.confidence != b.confidence { return a.confidence > b.confidence }
            if a.kind.specificity != b.kind.specificity { return a.kind.specificity > b.kind.specificity }
            if a.range.count != b.range.count { return a.range.count > b.range.count }
            if a.range.lowerBound != b.range.lowerBound { return a.range.lowerBound < b.range.lowerBound }
            return a.ruleID < b.ruleID
        }
        var kept: [SecretMatch] = []
        for h in sorted where !kept.contains(where: { $0.range.overlaps(h.range) }) {
            kept.append(h)
        }
        return kept.sorted { $0.range.lowerBound < $1.range.lowerBound }
    }
}
