// swift-tools-version: 6.2
import PackageDescription

// A test harness for production security/CSR code; the app and extension build in Xcode.
let package = Package(
    name: "SecureEnclaveTokenCore",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.4"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2")
    ],
    targets: [
        .target(name: "TokenCore", dependencies: [.product(name: "X509", package: "swift-certificates"), .product(name: "SwiftASN1", package: "swift-asn1"), .product(name: "ArgumentParser", package: "swift-argument-parser")], path: "Shared"),
        .testTarget(name: "TokenCoreTests", dependencies: ["TokenCore"], path: "Tests/TokenCoreTests")
    ]
)
