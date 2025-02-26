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
            dependencies: [],
            resources: [
                .process("Resources/Sbox_InvSbox_Rcon.txt")
            ]
        ),
        .testTarget(
                    name: "WhiteboxCryptographyTests",
                    dependencies: ["WhiteboxCryptography"]
                ),
    ]
)


