import Foundation

/// Coarse category used for grouping, masking and severity. Detector rules map onto these.
public enum SecretKind: String, Codable, Sendable, CaseIterable {
    case githubToken
    case awsAccessKeyID
    case awsSecretAccessKey
    case stripeKey
    case slackToken
    case openAIKey
    case anthropicKey
    case googleAPIKey
    /// Any other vendor-specific credential format (the rule's label carries the vendor name).
    case vendorAPIKey
    case privateKey
    case bearerToken
    case jwt
    case databaseURL
    case genericPassword
    case genericAPIKey
    case genericSecret

    public var displayName: String {
        switch self {
        case .githubToken: "GitHub token"
        case .awsAccessKeyID: "AWS access key ID"
        case .awsSecretAccessKey: "AWS secret access key"
        case .stripeKey: "Stripe key"
        case .slackToken: "Slack token"
        case .openAIKey: "OpenAI API key"
        case .anthropicKey: "Anthropic API key"
        case .googleAPIKey: "Google API key"
        case .vendorAPIKey: "API key"
        case .privateKey: "Private key"
        case .bearerToken: "Bearer token"
        case .jwt: "JWT"
        case .databaseURL: "Database URL with password"
        case .genericPassword: "Password"
        case .genericAPIKey: "API key"
        case .genericSecret: "Possible secret"
        }
    }

    /// Used to break ties between overlapping matches: a more specific detector wins.
    public var specificity: Int {
        if isVendorCredential { return 3 }
        switch self {
        case .jwt, .databaseURL: return 2
        case .bearerToken, .genericPassword, .genericAPIKey: return 1
        default: return 0
        }
    }

    /// Kinds that qualify for auto-redaction in "high confidence" mode when the rule also reports `.high`.
    public var isVendorCredential: Bool {
        switch self {
        case .githubToken, .awsAccessKeyID, .awsSecretAccessKey, .stripeKey, .slackToken,
             .openAIKey, .anthropicKey, .googleAPIKey, .vendorAPIKey, .privateKey:
            true
        default:
            false
        }
    }
}

public enum Confidence: String, Codable, Sendable, Comparable {
    case low, medium, high

    private var rank: Int {
        switch self { case .low: 0; case .medium: 1; case .high: 2 }
    }
    public static func < (a: Confidence, b: Confidence) -> Bool { a.rank < b.rank }
}
