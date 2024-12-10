// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "WhiteboxCryptography",
    platforms: [
        .iOS(.v13), .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "WhiteboxCryptography",
            targets: ["WhiteboxCryptography"]),
    ],
    targets: [
        .target(
            name: "WhiteboxCryptography",
            dependencies: []),
        .testTarget(
            name: "WhiteboxCryptographyTests",
            dependencies: ["WhiteboxCryptography"]),
    ]
)
