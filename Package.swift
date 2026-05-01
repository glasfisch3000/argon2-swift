// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "SwiftArgon2",
    platforms: [
        .macOS(.v15),
        .iOS(.v18)
    ],
    products: [
        .library(
            name: "SwiftArgon2",
            targets: ["SwiftArgon2"]
        ),
    ],
    targets: [
        .target(
            name: "SwiftArgon2",
            swiftSettings: [
                .define("MIMICLONE_SECURE_WIPE")
            ]
        ),
        .testTarget(
            name: "SwiftArgon2Tests",
            dependencies: ["SwiftArgon2"]
        ),
    ]
)
