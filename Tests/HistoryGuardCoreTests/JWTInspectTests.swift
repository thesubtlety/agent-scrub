import Foundation
import Testing
@testable import HistoryGuardCore

private func b64url(_ s: String) -> String {
    Data(s.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func jwt(payload: String) -> String {
    "\(b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")).\(b64url(payload)).abcdefghij1234567890"
}

@Suite struct JWTInspectTests {
    @Test func expiredTokenIsExpired() {
        #expect(JWTInspect.isExpired(jwt(payload: "{\"exp\":1000000000,\"sub\":\"u\"}")))   // 2001
    }

    @Test func futureAndMissingExpAreNotExpired() {
        #expect(!JWTInspect.isExpired(jwt(payload: "{\"exp\":9999999999,\"sub\":\"u\"}")))  // 2286
        #expect(!JWTInspect.isExpired(jwt(payload: "{\"sub\":\"u\"}")))                     // no exp
    }

    @Test func nonJWTIsNeverExpired() {
        #expect(!JWTInspect.isExpired("not.a.jwt"))
        #expect(!JWTInspect.isExpired("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"))
    }
}
