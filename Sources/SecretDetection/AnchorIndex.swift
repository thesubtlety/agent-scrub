import Foundation

/// Multi-pattern byte matcher (Aho–Corasick compiled to a flat DFA) over all rules' anchors. One pass over a
/// text yields, for every rule, the byte offsets where one of its anchors starts. Anchors are lower-case ASCII;
/// the input is the offset-preserving ASCII-lowercased text. One array lookup per input byte.
struct AnchorIndex: Sendable {
    /// transitions[state * 256 + byte] = next state (failure links already resolved).
    private let transitions: [Int32]
    /// outputs[state] = anchors ending here, as (rule index, anchor length).
    private let outputs: [[(rule: Int, length: Int)]]
    let ruleCount: Int

    init(anchorsByRule: [[String]]) {
        ruleCount = anchorsByRule.count
        var next: [[UInt8: Int]] = [[:]]
        var outs: [[(rule: Int, length: Int)]] = [[]]
        for (ruleIndex, anchors) in anchorsByRule.enumerated() {
            for anchor in anchors where !anchor.isEmpty {
                var cur = 0
                for b in anchor.utf8 {
                    if let n = next[cur][b] { cur = n } else {
                        next.append([:]); outs.append([])
                        next[cur][b] = next.count - 1
                        cur = next.count - 1
                    }
                }
                outs[cur].append((ruleIndex, anchor.utf8.count))
            }
        }
        let n = next.count
        var fail = [Int](repeating: 0, count: n)
        var table = [Int32](repeating: 0, count: n * 256)
        // Root: missing transitions stay at root.
        for (b, s) in next[0] { table[Int(b)] = Int32(s) }
        var queue: [Int] = Array(next[0].values)
        var head = 0
        while head < queue.count {
            let r = queue[head]; head += 1
            // Resolve every byte for state r: explicit edge, else follow failure state's resolved edge.
            for byte in 0..<256 {
                if let s = next[r][UInt8(byte)] {
                    table[r * 256 + byte] = Int32(s)
                    fail[s] = Int(table[fail[r] * 256 + byte])
                    outs[s] += outs[fail[s]]
                    queue.append(s)
                } else {
                    table[r * 256 + byte] = table[fail[r] * 256 + byte]
                }
            }
        }
        transitions = table
        outputs = outs
    }

    /// Per-rule precondition evaluated at hit time, before anything is recorded: one of `chars` must occur
    /// within `within` bytes after the anchor. Filters the bulk of hits for broad anchors like "token".
    struct NearCheck: Sendable {
        let chars: [Bool]   // 256 entries
        let within: Int
    }

    /// Start offsets of anchor hits, indexed by rule. Rules with no hits have an empty array.
    func hits(in lower: [UInt8], near: [NearCheck?]) -> [[Int]] {
        var out = [[Int]](repeating: [], count: ruleCount)
        var state = 0
        let n = lower.count
        lower.withUnsafeBufferPointer { text in
            transitions.withUnsafeBufferPointer { t in
                for i in 0..<n {
                    state = Int(t[state &* 256 &+ Int(text[i])])
                    let o = outputs[state]
                    if o.isEmpty { continue }
                    for hit in o {
                        if let check = near[hit.rule] {
                            let from = i + 1
                            let end = min(n, from + check.within)
                            var ok = false
                            var k = from
                            while k < end { if check.chars[Int(text[k])] { ok = true; break }; k += 1 }
                            if !ok { continue }
                        }
                        out[hit.rule].append(i + 1 - hit.length)
                    }
                }
            }
        }
        return out
    }
}
