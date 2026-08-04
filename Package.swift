// swift-tools-version:6.4
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

import class Foundation.ProcessInfo

let swiftSettings: [SwiftSetting] = [
    .enableExperimentalFeature("Lifetimes"),
]

// SwiftPM resources generate a Foundation.Bundle accessor. Embedded builds do not have Foundation,
// and Package.swift is evaluated for the host platform when cross-compiling. Keep the privacy
// manifest opt-in so embedded and non-Darwin cross-compilation do not accidentally link Foundation.
let includePrivacyManifest: Bool = {
    #if canImport(Darwin)
    return ProcessInfo.processInfo.environment["SWIFT_CRYPTO_ENABLE_PRIVACY_MANIFEST"] == "1"
    #else
    return false
    #endif
}()

let privacyManifestExclude: [String] = includePrivacyManifest ? [] : ["PrivacyInfo.xcprivacy"]
let privacyManifestResource: [PackageDescription.Resource] =
    includePrivacyManifest ? [.copy("PrivacyInfo.xcprivacy")] : []

let package = Package(
    name: "swift-crypto",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .watchOS(.v26),
        .tvOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
    ],
    dependencies: [
        // The Pure Swift backend is provided by swift-ssl/SSLCrypto.
        .package(name: "swift-ssl", path: "../swift-ssl"),
    ],
    targets: [
        .target(
            name: "Crypto",
            dependencies: [
                .product(name: "SSLCrypto", package: "swift-ssl"),
            ],
            exclude: privacyManifestExclude + ["Docs.docc"],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings + [.define("SWIFT_CRYPTO_PURE_SWIFT")]
        ),
        .executableTarget(name: "crypto-shasum", dependencies: ["Crypto"]),
        .executableTarget(
            name: "crypto-digest-validation",
            dependencies: ["Crypto"]
        ),
        .testTarget(
            name: "CryptoTests",
            dependencies: ["Crypto"],
            resources: [
                .copy("HPKE/hpke-test-vectors.json"),
                .copy("KEM/MLKEM768_BSSLKAT.json"),
                .copy("KEM/MLKEM768KAT.json"),
                .copy("KEM/MLKEM1024_BSSLKAT.json"),
                .copy("KEM/MLKEM1024KAT.json"),
                .copy("KEM/test-vectors.json"),
                .copy("Signatures/MLDSA/MLDSA65_KeyGen_KAT.json"),
                .copy("Signatures/MLDSA/MLDSA87_KeyGen_KAT.json"),
            ],
            swiftSettings: swiftSettings
        ),
    ]
)

// ---    STANDARD CROSS-REPO SETTINGS DO NOT EDIT   --- //
for target in package.targets {
    switch target.type {
    case .regular, .test, .executable:
        var settings = target.swiftSettings ?? []
        // https://github.com/swiftlang/swift-evolution/blob/main/proposals/0444-member-import-visibility.md
        settings.append(.enableUpcomingFeature("MemberImportVisibility"))
        target.swiftSettings = settings
    case .macro, .plugin, .system, .binary:
        ()  // not applicable
    @unknown default:
        ()  // we don't know what to do here, do nothing
    }
}
// --- END: STANDARD CROSS-REPO SETTINGS DO NOT EDIT --- //
