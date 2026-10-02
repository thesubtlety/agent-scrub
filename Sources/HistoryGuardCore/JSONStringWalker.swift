import Foundation

/// A string value found inside a JSON document, with the information needed to map decoded text back to bytes.
public struct JSONStringValue: Sendable {
    /// RFC 6901 JSON pointer to this value, e.g. "/message/content/0/text".
    public let pointer: String
    /// Decoded (unescaped) text.
    public let text: String
    /// Serialized byte range of the string *body* (between the quotes), relative to the document start.
    public let bodyRange: Range<Int>
    /// offsetMap[i] = serialized byte offset of decoded UTF-8 byte i; count == text.utf8.count + 1.
    /// nil when the body is plain ASCII with no escapes: decoded byte i is at bodyRange.lowerBound + i.
    public let offsetMap: [Int]?
    public let hasEscapes: Bool
}

public enum JSONWalkError: Error, Equatable, Sendable {
    case unexpectedEnd(offset: Int)
    case unexpectedByte(UInt8, offset: Int)
    case invalidEscape(offset: Int)
    case invalidUTF8(offset: Int)
    case tooDeeplyNested(offset: Int)
}

/// Minimal, allocation-conscious JSON tokenizer that yields every string *value* (object keys are skipped)
/// together with a JSON pointer and a byte offset map. It does not build a tree.
public struct JSONStringWalker: Sendable {
    /// Minimum decoded length for a string to be reported. Very short strings cannot hold a secret.
    public var minimumLength: Int = 6

    public init(minimumLength: Int = 6) { self.minimumLength = minimumLength }

    public func strings(in bytes: some Collection<UInt8>) throws -> [JSONStringValue] {
        let arr = Array(bytes)
        var out: [JSONStringValue] = []
        var p = Parser(bytes: arr, minLen: minimumLength)
        try p.parseValue(path: "", into: &out)
        p.skipWS()
        if p.i != arr.count { throw JSONWalkError.unexpectedByte(arr[p.i], offset: p.i) }
        return out
    }

    private struct Parser {
        let bytes: [UInt8]
        let minLen: Int
        var i = 0
        var depth = 0
        let maxDepth = 512   // guard against stack overflow from pathologically nested input

        init(bytes: [UInt8], minLen: Int) {
            self.bytes = bytes
            self.minLen = minLen
        }

        mutating func skipWS() {
            while i < bytes.count, bytes[i] == 0x20 || bytes[i] == 0x0A || bytes[i] == 0x0D || bytes[i] == 0x09 { i += 1 }
        }

        mutating func expect(_ b: UInt8) throws {
            guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
            guard bytes[i] == b else { throw JSONWalkError.unexpectedByte(bytes[i], offset: i) }
            i += 1
        }

        mutating func parseValue(path: String, into out: inout [JSONStringValue]) throws {
            skipWS()
            guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
            switch bytes[i] {
            case UInt8(ascii: "{"):
                depth += 1; defer { depth -= 1 }
                guard depth <= maxDepth else { throw JSONWalkError.tooDeeplyNested(offset: i) }
                try parseObject(path: path, into: &out)
            case UInt8(ascii: "["):
                depth += 1; defer { depth -= 1 }
                guard depth <= maxDepth else { throw JSONWalkError.tooDeeplyNested(offset: i) }
                try parseArray(path: path, into: &out)
            case UInt8(ascii: "\""):
                if let v = try parseString(pointer: path, report: true) { out.append(v) }
            case UInt8(ascii: "t"): try literal("true")
            case UInt8(ascii: "f"): try literal("false")
            case UInt8(ascii: "n"): try literal("null")
            default: try parseNumber()
            }
        }

        mutating func literal(_ s: StaticString) throws {
            let n = s.utf8CodeUnitCount
            guard i + n <= bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
            var ok = true
            s.withUTF8Buffer { buf in
                for k in 0..<n where bytes[i + k] != buf[k] { ok = false }
            }
            guard ok else { throw JSONWalkError.unexpectedByte(bytes[i], offset: i) }
            i += n
        }

        mutating func parseNumber() throws {
            let start = i
            while i < bytes.count {
                let b = bytes[i]
                if (b >= 0x30 && b <= 0x39) || b == UInt8(ascii: "-") || b == UInt8(ascii: "+")
                    || b == UInt8(ascii: ".") || b == UInt8(ascii: "e") || b == UInt8(ascii: "E") {
                    i += 1
                } else { break }
            }
            if i == start { throw JSONWalkError.unexpectedByte(bytes[i], offset: i) }
        }

        mutating func parseObject(path: String, into out: inout [JSONStringValue]) throws {
            try expect(UInt8(ascii: "{"))
            skipWS()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") { i += 1; return }
            while true {
                skipWS()
                guard let key = try parseString(pointer: "", report: false, force: true) else {
                    throw JSONWalkError.unexpectedEnd(offset: i)
                }
                skipWS()
                try expect(UInt8(ascii: ":"))
                try parseValue(path: path + "/" + escapePointer(key.text), into: &out)
                skipWS()
                guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return }
                throw JSONWalkError.unexpectedByte(bytes[i], offset: i)
            }
        }

        mutating func parseArray(path: String, into out: inout [JSONStringValue]) throws {
            try expect(UInt8(ascii: "["))
            skipWS()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") { i += 1; return }
            var idx = 0
            while true {
                try parseValue(path: path + "/\(idx)", into: &out)
                idx += 1
                skipWS()
                guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return }
                throw JSONWalkError.unexpectedByte(bytes[i], offset: i)
            }
        }

        func escapePointer(_ s: String) -> String {
            s.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
        }

        /// Parses a string starting at the opening quote. Returns nil when `report` is false or the string is too short.
        /// `force` returns the value regardless of length (used for object keys).
        mutating func parseString(pointer: String, report: Bool, force: Bool = false) throws -> JSONStringValue? {
            try expect(UInt8(ascii: "\""))
            let bodyStart = i
            var decoded: [UInt8] = []
            var map: [Int]? = nil
            var hasEscapes = false
            decoded.reserveCapacity(64)
            // Identity mapping holds until the first escape or non-ASCII byte; only then materialise the map.
            func materialise() {
                if map == nil { map = (0..<decoded.count).map { bodyStart + $0 } }
            }

            while true {
                guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
                let b = bytes[i]
                if b == UInt8(ascii: "\"") { break }
                if b == UInt8(ascii: "\\") {
                    hasEscapes = true
                    materialise()
                    let escStart = i
                    i += 1
                    guard i < bytes.count else { throw JSONWalkError.unexpectedEnd(offset: i) }
                    let e = bytes[i]
                    i += 1
                    var scalar: UInt32
                    switch e {
                    case UInt8(ascii: "\""): scalar = 0x22
                    case UInt8(ascii: "\\"): scalar = 0x5C
                    case UInt8(ascii: "/"): scalar = 0x2F
                    case UInt8(ascii: "b"): scalar = 0x08
                    case UInt8(ascii: "f"): scalar = 0x0C
                    case UInt8(ascii: "n"): scalar = 0x0A
                    case UInt8(ascii: "r"): scalar = 0x0D
                    case UInt8(ascii: "t"): scalar = 0x09
                    case UInt8(ascii: "u"):
                        scalar = try hex4(at: i)
                        i += 4
                        if scalar >= 0xD800, scalar <= 0xDBFF {
                            // surrogate pair
                            guard i + 6 <= bytes.count, bytes[i] == UInt8(ascii: "\\"), bytes[i + 1] == UInt8(ascii: "u") else {
                                throw JSONWalkError.invalidEscape(offset: escStart)
                            }
                            let lo = try hex4(at: i + 2)
                            guard lo >= 0xDC00, lo <= 0xDFFF else { throw JSONWalkError.invalidEscape(offset: escStart) }
                            i += 6
                            scalar = 0x10000 + ((scalar - 0xD800) << 10) + (lo - 0xDC00)
                        } else if scalar >= 0xDC00, scalar <= 0xDFFF {
                            throw JSONWalkError.invalidEscape(offset: escStart)
                        }
                    default:
                        throw JSONWalkError.invalidEscape(offset: escStart)
                    }
                    guard let u = Unicode.Scalar(scalar) else { throw JSONWalkError.invalidEscape(offset: escStart) }
                    for byte in String(u).utf8 {
                        decoded.append(byte)
                        map!.append(escStart)
                    }
                    continue
                }
                if b < 0x20 { throw JSONWalkError.unexpectedByte(b, offset: i) }
                if b >= 0x80 { hasEscapes = true; materialise() }
                decoded.append(b)
                map?.append(i)
                i += 1
            }
            let bodyEnd = i
            i += 1 // closing quote
            map?.append(bodyEnd)

            if !force, !report { return nil }
            if !force, decoded.count < minLen { return nil }
            guard let text = String(bytes: decoded, encoding: .utf8) else {
                throw JSONWalkError.invalidUTF8(offset: bodyStart)
            }
            return JSONStringValue(pointer: pointer, text: text, bodyRange: bodyStart..<bodyEnd,
                                   offsetMap: map, hasEscapes: hasEscapes)
        }

        func hex4(at off: Int) throws -> UInt32 {
            guard off + 4 <= bytes.count else { throw JSONWalkError.unexpectedEnd(offset: off) }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = bytes[off + k]
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c - 0x30)
                case 0x41...0x46: d = UInt32(c - 0x41 + 10)
                case 0x61...0x66: d = UInt32(c - 0x61 + 10)
                default: throw JSONWalkError.invalidEscape(offset: off)
                }
                v = v << 4 | d
            }
            return v
        }
    }
}
