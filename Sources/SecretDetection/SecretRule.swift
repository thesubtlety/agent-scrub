import Foundation
import HistoryGuardCore

public enum Canonicalizer: String, Codable, Sendable {
    /// Use the matched bytes as-is.
    case identity
    /// Strip all whitespace between the PEM header and footer so line-wrapping and escaping don't change identity.
    case pem
    /// Trim trailing punctuation that commonly clings to URLs in prose.
    case url

    /// The part of the raw regex match that is actually the secret. Used to shrink the reported range so a
    /// redactor never overwrites bytes that are not part of the credential (e.g. the period after a URL).
    public func trimmedMatch(_ s: Substring) -> Substring {
        switch self {
        case .identity, .pem:
            return s
        case .url:
            var t = s
            while let last = t.last, ".,;)]}".contains(last) { t.removeLast() }
            return t
        }
    }

    public func canonicalize(_ s: String) -> Data {
        switch self {
        case .identity, .url:
            return Data(s.utf8)
        case .pem:
            return Data(s.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) }.map { UInt8(truncatingIfNeeded: $0.value) })
        }
    }
}

/// Bytes before and after an anchor hit that must be searched for the rule to see a complete match.
/// `after` must exceed the rule's maximum match length or a match could be truncated at the window edge.
public struct WindowSpec: Codable, Sendable, Hashable {
    public var before: Int
    public var after: Int
}

/// Cheap byte-level precondition: one of `chars` must occur within `within` bytes after an anchor hit.
/// Lets keyword rules skip prose ("the token count") without running the regex.
public struct NearSpec: Codable, Sendable, Hashable {
    public var chars: String
    public var within: Int
}

/// gitleaks-style allowlist: a finding is dropped when it matches. `target` selects what the regexes see.
public struct AllowlistSpec: Codable, Sendable, Hashable {
    public enum Target: String, Codable, Sendable { case secret, match, line }
    public var target: Target
    public var condition: String?
    public var regexes: [String]?
    public var stopwords: [String]?
}

public struct CompiledAllowlist: @unchecked Sendable {
    public let target: AllowlistSpec.Target
    public let requiresAll: Bool
    public let regexes: [Regex<AnyRegexOutput>]
    public let stopwords: [String]

    init(_ spec: AllowlistSpec) throws {
        target = spec.target
        requiresAll = spec.condition?.uppercased() == "AND"
        regexes = try (spec.regexes ?? []).map { try Regex($0) }
        stopwords = (spec.stopwords ?? []).map { $0.lowercased() }
    }

    /// Mirrors gitleaks: regexes run against the chosen target, stopwords always against the lowercased secret.
    func allows(secret: String, match: Substring, line: Substring) -> Bool {
        let subject: Substring
        switch target {
        case .secret: subject = Substring(secret)
        case .match: subject = match
        case .line: subject = line
        }
        let regexAllowed = regexes.contains { subject.contains($0) }
        let lowered = secret.lowercased()
        // Match a stopword only as a delimited word, not any substring: "master" inside a random run like
        // "xq7masterv8kd" must NOT drop the value (that was silently killing real secrets), while a delimited
        // "my_password" still does.
        let stopwordHit = stopwords.contains { Self.containsWord(lowered, $0) }
        if requiresAll {
            var checks: [Bool] = []
            if !regexes.isEmpty { checks.append(regexAllowed) }
            if !stopwords.isEmpty { checks.append(stopwordHit) }
            return !checks.isEmpty && checks.allSatisfy { $0 }
        }
        return regexAllowed || stopwordHit
    }

    /// True if `word` occurs in `haystack` bounded by non-alphanumeric edges (string start/end or a separator like
    /// `_`/`-`/`.`). Alphanumeric neighbours mean it's part of a larger token, not a standalone word, so it doesn't
    /// count — which keeps high-entropy secrets that merely embed a common word.
    static func containsWord(_ haystack: String, _ word: String) -> Bool {
        guard !word.isEmpty else { return false }
        let h = Array(haystack), w = Array(word)
        guard h.count >= w.count else { return false }
        func isWordChar(_ c: Character) -> Bool { c.isLetter || c.isNumber }
        var i = 0
        while i <= h.count - w.count {
            if Array(h[i..<(i + w.count)]) == w,
               (i == 0 || !isWordChar(h[i - 1])),
               (i + w.count == h.count || !isWordChar(h[i + w.count])) {
                return true
            }
            i += 1
        }
        return false
    }
}

public struct MaskSpec: Codable, Sendable, Hashable {
    public var prefix: Int
    public var suffix: Int
}

/// A single data-driven detector. Loaded from rules.json, compiled once.
public struct SecretRule: @unchecked Sendable {
    public let id: String
    /// "gitleaks" or "custom".
    public let source: String
    /// Short human label used for identity aliases.
    public let label: String
    public let kind: SecretKind
    public let confidence: Confidence
    public let regex: Regex<AnyRegexOutput>
    public let requiredContext: [Regex<AnyRegexOutput>]
    public let excludedContext: [Regex<AnyRegexOutput>]
    public let canonicalizer: Canonicalizer
    public let mask: MaskSpec
    public let multiline: Bool
    /// Lower-case literal substrings, at least one of which must appear in the text before the regex is tried.
    /// A cheap prefilter: most transcript strings contain none of them and skip the regex engine entirely.
    public let anchors: [String]
    public let window: WindowSpec
    public let requireNear: NearSpec?
    /// gitleaks semantics: drop the finding when the secret's Shannon entropy is <= this value.
    public let minEntropy: Double?
    /// 1-based capture group holding the secret; nil means named group "secret", else first non-empty group, else whole match.
    public let secretGroup: Int?
    public let allowlists: [CompiledAllowlist]
    /// Offline format validator id, e.g. "github-crc32".
    public let validator: String?
    /// The regex compiled with a leading ^; present when an anchor hit is exactly where the match must start.
    public let anchoredRegex: Regex<AnyRegexOutput>?
    /// "keyed" rules are Layer B: the key name is the evidence; value plausibility is checked by entropy.
    public let isKeyed: Bool

    /// Namespace used in fingerprinting. Rules of the same kind share identity so a GitHub token found by two
    /// GitHub rules is one secret.
    public var namespace: String { kind.rawValue }
}

struct RuleFile: Decodable {
    struct Entry: Decodable {
        let id: String
        let source: String?
        let label: String?
        let kind: SecretKind
        let confidence: Confidence
        let pattern: String
        let requiredContext: [String]?
        let excludedContext: [String]?
        let canonicalizer: Canonicalizer?
        let mask: MaskSpec
        let multiline: Bool?
        let layer: String?
        let anchors: [String]?
        let window: WindowSpec?
        let requireNear: NearSpec?
        let minEntropy: Double?
        let secretGroup: Int?
        let allowlists: [AllowlistSpec]?
        let validator: String?
        let anchoredAtHit: Bool?
    }
    let version: Int
    let rules: [Entry]
    let placeholders: [String]
    let globalAllowlists: [AllowlistSpec]?
}

/// A rule whose regex (or allowlist regex) the Swift engine could not compile. Surfaced, never silently dropped.
public struct RejectedRule: Sendable, Hashable {
    public let id: String
    public let error: String
}

public struct RuleCatalog: @unchecked Sendable {
    public let rules: [SecretRule]
    public let placeholders: [Regex<AnyRegexOutput>]
    public let globalAllowlists: [CompiledAllowlist]
    public let version: Int
    public let rejected: [RejectedRule]

    public static func bundled() throws -> RuleCatalog {
        guard let url = Bundle.module.url(forResource: "rules", withExtension: "json") else {
            throw CocoaError(.fileNoSuchFile)
        }
        return try RuleCatalog(data: Data(contentsOf: url))
    }

    /// Development aid: a catalog restricted to the given rule ids (all rules when `ids` is empty).
    public func filtered(ids: Set<String>) -> RuleCatalog {
        ids.isEmpty ? self : RuleCatalog(rules: rules.filter { ids.contains($0.id) }, placeholders: placeholders,
                                         globalAllowlists: globalAllowlists, version: version, rejected: rejected)
    }

    init(rules: [SecretRule], placeholders: [Regex<AnyRegexOutput>], globalAllowlists: [CompiledAllowlist], version: Int, rejected: [RejectedRule]) {
        self.rules = rules
        self.placeholders = placeholders
        self.globalAllowlists = globalAllowlists
        self.version = version
        self.rejected = rejected
    }

    static func anchored(_ pattern: String) -> String {
        pattern.hasPrefix("(?i)") ? "(?i)^" + pattern.dropFirst(4) : "^" + pattern
    }

    public init(data: Data) throws {
        let file = try JSONDecoder().decode(RuleFile.self, from: data)
        version = file.version
        var compiled: [SecretRule] = []
        var rejected: [RejectedRule] = []
        for e in file.rules {
            do {
                compiled.append(SecretRule(
                    id: e.id,
                    source: e.source ?? "custom",
                    label: e.label ?? e.kind.displayName,
                    kind: e.kind,
                    confidence: e.confidence,
                    regex: try Regex(e.pattern),
                    requiredContext: try (e.requiredContext ?? []).map { try Regex($0) },
                    excludedContext: try (e.excludedContext ?? []).map { try Regex($0) },
                    canonicalizer: e.canonicalizer ?? .identity,
                    mask: e.mask,
                    multiline: e.multiline ?? false,
                    anchors: (e.anchors ?? []).map { $0.lowercased() },
                    window: e.window ?? WindowSpec(before: 64, after: 4096),
                    requireNear: e.requireNear,
                    minEntropy: e.minEntropy,
                    secretGroup: e.secretGroup,
                    allowlists: try (e.allowlists ?? []).map { try CompiledAllowlist($0) },
                    validator: e.validator,
                    anchoredRegex: (e.anchoredAtHit ?? false) ? try Regex(Self.anchored(e.pattern)) : nil,
                    isKeyed: e.layer == "keyed"
                ))
            } catch {
                rejected.append(RejectedRule(id: e.id, error: String(describing: error)))
            }
        }
        rules = compiled
        self.rejected = rejected
        placeholders = try file.placeholders.map { try Regex($0) }
        globalAllowlists = try (file.globalAllowlists ?? []).map { try CompiledAllowlist($0) }
    }
}
