// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "goodboy-engine",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "FlowEngine", targets: ["FlowEngine"]),
        .library(name: "EngineMCP", targets: ["EngineMCP"]),
        .library(name: "EngineTools", targets: ["EngineTools"]),
        .executable(name: "goodboy-mcp", targets: ["goodboy-mcp"])
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.0"),
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0")
    ],
    targets: [
        .target(
            name: "FlowEngine",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift")
            ],
            exclude: ["Protocol/README.md"]
        ),
        .target(
            name: "EngineMCP",
            dependencies: [
                "FlowEngine",
                .product(name: "MCP", package: "swift-sdk")
            ]
        ),
        .target(
            name: "EngineTools",
            dependencies: ["FlowEngine", "EngineMCP"]
        ),
        .executableTarget(
            name: "goodboy-mcp",
            dependencies: [
                "FlowEngine", "EngineTools", "EngineMCP",
                .product(name: "MCP", package: "swift-sdk")
            ]
        ),
        .testTarget(
            name: "FlowEngineTests",
            dependencies: ["FlowEngine"]
        ),
        .testTarget(
            name: "EngineToolsTests",
            dependencies: ["FlowEngine", "EngineTools"]
        )
    ]
)
