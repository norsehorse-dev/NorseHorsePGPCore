// swift-tools-version: 5.9
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse
import PackageDescription

let package = Package(
    name: "NorseHorsePGPCore",
    platforms: [
        // iOS-only for now: the card transport uses CoreNFC. A future macOS target
        // would introduce an `OpenPGPCardTransport` seam (NFC on iOS, PC/SC via
        // CryptoTokenKit on macOS) — see README "Roadmap".
        .iOS(.v17)
    ],
    products: [
        .library(name: "NorseHorsePGPCore", targets: ["NorseHorsePGPCore"])
    ],
    targets: [
        .target(
            name: "NorseHorsePGPCore",
            path: "Sources/NorseHorsePGPCore"
        ),
        .testTarget(
            name: "NorseHorsePGPCoreTests",
            dependencies: ["NorseHorsePGPCore"],
            path: "Tests/NorseHorsePGPCoreTests"
        )
    ]
)
