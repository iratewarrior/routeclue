// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunnelGuard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "TunnelGuardCore", targets: ["TunnelGuardCore"]),
        .executable(name: "tunnelguard", targets: ["TunnelGuardCLI"]),
        .executable(name: "TunnelGuardApp", targets: ["TunnelGuardApp"]),
        .executable(name: "TunnelGuardSelfTest", targets: ["TunnelGuardSelfTest"]),
    ],
    targets: [
        .target(name: "TunnelGuardCore"),
        .executableTarget(name: "TunnelGuardCLI", dependencies: ["TunnelGuardCore"]),
        .executableTarget(name: "TunnelGuardApp", dependencies: ["TunnelGuardCore"]),
        .executableTarget(name: "TunnelGuardSelfTest", dependencies: ["TunnelGuardCore"]),
    ],
    swiftLanguageModes: [.v5]
)
