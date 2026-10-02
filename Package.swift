// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HistoryGuard",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HistoryGuardCore", targets: ["HistoryGuardCore"]),
        .library(name: "SecretDetection", targets: ["SecretDetection"]),
        .library(name: "ClaudeCodeAdapter", targets: ["ClaudeCodeAdapter"]),
        .library(name: "CodexAdapter", targets: ["CodexAdapter"]),
        .library(name: "GeminiAdapter", targets: ["GeminiAdapter"]),
        .library(name: "VSCodeAdapter", targets: ["VSCodeAdapter"]),
        .library(name: "ClineAdapter", targets: ["ClineAdapter"]),
        .library(name: "AiderAdapter", targets: ["AiderAdapter"]),
        .library(name: "ContinueAdapter", targets: ["ContinueAdapter"]),
        .library(name: "PiAdapter", targets: ["PiAdapter"]),
        .library(name: "HistoryGuardDB", targets: ["HistoryGuardDB"]),
        .library(name: "StoreMonitoring", targets: ["StoreMonitoring"]),
        .executable(name: "hgctl", targets: ["hgctl"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "HistoryGuardCore",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "SecretDetection",
            dependencies: ["HistoryGuardCore"],
            resources: [.copy("Resources/rules.json")]
        ),
        .target(
            name: "ClaudeCodeAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .target(
            name: "GeminiAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .systemLibrary(name: "CSQLite", path: "Sources/CSQLite"),
        .target(name: "SQLiteSupport", dependencies: ["CSQLite", "HistoryGuardCore"]),
        .target(
            name: "CodexAdapter",
            dependencies: ["HistoryGuardCore", "SQLiteSupport"]
        ),
        .target(
            name: "VSCodeAdapter",
            dependencies: ["HistoryGuardCore", "SQLiteSupport"]
        ),
        .target(
            name: "ClineAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .target(
            name: "AiderAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .target(
            name: "ContinueAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .target(
            name: "PiAdapter",
            dependencies: ["HistoryGuardCore"]
        ),
        .executableTarget(
            name: "hgctl",
            dependencies: [
                "HistoryGuardCore", "SecretDetection", "ClaudeCodeAdapter", "CodexAdapter", "GeminiAdapter", "VSCodeAdapter", "ClineAdapter", "AiderAdapter", "ContinueAdapter", "PiAdapter",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(name: "HistoryGuardDB", dependencies: ["SQLiteSupport", "HistoryGuardCore"]),
        .target(name: "StoreMonitoring", dependencies: ["SecretDetection", "HistoryGuardCore", "HistoryGuardDB"]),
        .testTarget(name: "HistoryGuardCoreTests", dependencies: ["HistoryGuardCore"]),
        .testTarget(name: "SecretDetectionTests", dependencies: ["SecretDetection"]),
        .testTarget(name: "ClaudeCodeAdapterTests", dependencies: ["ClaudeCodeAdapter", "SecretDetection"]),
        .testTarget(name: "CodexAdapterTests", dependencies: ["CodexAdapter", "SecretDetection", "SQLiteSupport"]),
        .testTarget(name: "GeminiAdapterTests", dependencies: ["GeminiAdapter", "SecretDetection"]),
        .testTarget(name: "VSCodeAdapterTests", dependencies: ["VSCodeAdapter", "SecretDetection", "SQLiteSupport"]),
        .testTarget(name: "ClineAdapterTests", dependencies: ["ClineAdapter", "SecretDetection"]),
        .testTarget(name: "AiderAdapterTests", dependencies: ["AiderAdapter", "SecretDetection"]),
        .testTarget(name: "ContinueAdapterTests", dependencies: ["ContinueAdapter", "SecretDetection"]),
        .testTarget(name: "PiAdapterTests", dependencies: ["PiAdapter", "SecretDetection"]),
        .testTarget(name: "HistoryGuardDBTests", dependencies: ["HistoryGuardDB"]),
        .testTarget(name: "SQLiteSupportTests", dependencies: ["SQLiteSupport"]),
        .testTarget(name: "StoreMonitoringTests",
                    dependencies: ["StoreMonitoring", "HistoryGuardDB", "ClaudeCodeAdapter", "SecretDetection"]),
    ],
    swiftLanguageModes: [.v6]
)

#if os(macOS)
package.products.append(.executable(name: "HistoryGuardApp", targets: ["HistoryGuardApp"]))
package.products.append(.library(name: "KeychainSupport", targets: ["KeychainSupport"]))
package.targets.append(.target(name: "KeychainSupport", dependencies: ["HistoryGuardCore"]))
package.targets.append(.testTarget(name: "KeychainSupportTests", dependencies: ["KeychainSupport", "HistoryGuardCore"]))
package.targets.append(.executableTarget(
    name: "HistoryGuardApp",
    dependencies: ["StoreMonitoring", "SecretDetection", "ClaudeCodeAdapter", "CodexAdapter", "GeminiAdapter",
                   "VSCodeAdapter", "ClineAdapter", "AiderAdapter", "ContinueAdapter", "PiAdapter", "KeychainSupport", "HistoryGuardCore"]))
#endif
