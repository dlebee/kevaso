// swift-tools-version:5.9
// The Kevaso panes client for macOS (design §10.1): the sealed pane view, the API client, and a
// minimal app around them. `swift test` runs the hostile-pane regression suite.
import PackageDescription

let package = Package(
    name: "KevasoPanes",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "PaneKit", targets: ["PaneKit"]),
        .executable(name: "KevasoPanes", targets: ["KevasoPanes"]),
    ],
    targets: [
        .target(name: "PaneKit"),
        .executableTarget(name: "KevasoPanes", dependencies: ["PaneKit"]),
        .testTarget(name: "PaneKitTests", dependencies: ["PaneKit"],
                    resources: [.copy("Hostile")]),
    ]
)
