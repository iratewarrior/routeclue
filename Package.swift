// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RouteClue",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "RouteClueCore", targets: ["RouteClueCore"]),
        .executable(name: "routeclue", targets: ["RouteClueCLI"]),
        .executable(name: "RouteClueApp", targets: ["RouteClueApp"]),
        .executable(name: "RouteClueSelfTest", targets: ["RouteClueSelfTest"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(name: "RouteClueCore"),
        .executableTarget(
            name: "RouteClueCLI",
            dependencies: [
                "RouteClueCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .executableTarget(name: "RouteClueApp", dependencies: ["RouteClueCore"]),
        .executableTarget(name: "RouteClueSelfTest", dependencies: ["RouteClueCore"]),
    ],
    swiftLanguageModes: [.v6]
)
