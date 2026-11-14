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
        // Pinned liboqs build (ML-KEM-768 and SHA3-256). The PQC sources import
        // its COQS module. Vendored so the package builds out of the box and the
        // exact binary is on record: see Vendor/LIBOQS.md for version and hashes.
        .binaryTarget(
            name: "liboqs",
            path: "Vendor/liboqs.xcframework"
        ),
        .target(
            name: "NorseHorsePGPCore",
            dependencies: ["liboqs"],
            path: "Sources/NorseHorsePGPCore"
        ),
        .testTarget(
            name: "NorseHorsePGPCoreTests",
            dependencies: ["NorseHorsePGPCore"],
            path: "Tests/NorseHorsePGPCoreTests"
        )
    ]
)
