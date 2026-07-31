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

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CCryptoBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: 0226f30467f540a3f62ef48d453f93927da199b6

import PackageDescription

import class Foundation.ProcessInfo

// NOTE: To develop the the non-Darwin Crypto target on macOS, use a Dev Container.
let nonDarwinPlatforms: [Platform] = [
    .linux,
    .android,
    .windows,
    .wasi,
    .openbsd,
    // PackageDescription 6.4 exposes the typed FreeBSD constant as unavailable.
    // The custom spelling is the current manifest representation of the FreeBSD platform.
    .custom("freebsd"),
]

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

let includePerformanceValidation =
    ProcessInfo.processInfo.environment["SWIFT_CRYPTO_ENABLE_PERFORMANCE_VALIDATION"] == "1"

let privacyManifestExclude: [String] = includePrivacyManifest ? [] : ["PrivacyInfo.xcprivacy"]
let privacyManifestResource: [PackageDescription.Resource] =
    includePrivacyManifest ? [.copy("PrivacyInfo.xcprivacy")] : []

let package = Package(
    name: "swift-crypto",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .watchOS(.v11),
        .tvOS(.v18),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
        .library(name: "CryptoExtras", targets: ["CryptoExtras"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CCryptoBoringSSL", type: .static, targets: ["CCryptoBoringSSL"]),
            MANGLE_END */
    ],
    dependencies: [
        // Dependencies are added below so that they can be switched between local and absolute URLs
    ],
    targets: [
        .target(
            name: "CCryptoBoringSSL",
            exclude: privacyManifestExclude + [
                "hash.txt",
                "CMakeLists.txt",
                /*
                 * These files are excluded to support WASI libc which doesn't provide <netdb.h>.
                 * This is safe for all platforms as we do not rely on networking features.
                 */
                "crypto/bio/connect.cc",
                "crypto/bio/socket_helper.cc",
                "crypto/bio/socket.cc",
            ],
            resources: privacyManifestResource,
            cSettings: [
                // These defines come from BoringSSL's build system
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [Platform.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [Platform.windows])),
                .define("NOMINMAX", .when(platforms: [Platform.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [Platform.windows])),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
                .define(
                    "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
                    .when(platforms: [Platform.wasi])
                ),
                .define("OPENSSL_NO_ASM", .when(platforms: [Platform.wasi])),
            ]
        ),
        .target(
            name: "CXKCP",
            exclude: [
                "CMakeLists.txt"
            ],
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("high"),
                .headerSearchPath("low"),
                .headerSearchPath("low/KeccakP-1600"),
                .headerSearchPath("low/common"),
                .headerSearchPath("common"),
            ]
        ),
        .target(
            name: "CCryptoBoringSSLShims",
            dependencies: ["CCryptoBoringSSL"],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
        .target(
            name: "CXKCPShims",
            dependencies: ["CXKCP"],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
        .target(
            name: "Crypto",
            dependencies: [
                .target(name: "CCryptoBoringSSL", condition: .when(platforms: nonDarwinPlatforms)),
                .target(name: "CCryptoBoringSSLShims", condition: .when(platforms: nonDarwinPlatforms)),
                .target(name: "CryptoBoringWrapper", condition: .when(platforms: nonDarwinPlatforms)),
                .target(name: "CXKCP", condition: .when(platforms: nonDarwinPlatforms)),
                .target(name: "CXKCPShims", condition: .when(platforms: nonDarwinPlatforms)),
            ],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt",
                "Docs.docc",
                "vendored-sources.txt",
                "Signatures/BoringSSL/MLDSA_boring.swift.gyb",
                "KEM/BoringSSL/MLKEM_boring.swift.gyb",
            ],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings
        ),
        .target(
            name: "CryptoExtras",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
                "CryptoBoringWrapper",
                "Crypto",
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt",
                "Docs.docc"
            ],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings
        ),
        .target(
            name: "CryptoBoringWrapper",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
            ],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings
        ),
        .executableTarget(name: "crypto-shasum", dependencies: ["Crypto"]),
        .executableTarget(
            name: "crypto-digest-validation",
            dependencies: ["Crypto"]
        ),
        .executableTarget(
            name: "crypto-capability-validation",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
                "CryptoBoringWrapper",
                "Crypto",
                "CryptoExtras",
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
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
        .testTarget(
            name: "CryptoExtrasTests",
            dependencies: ["CryptoExtras", "Crypto"],
            resources: [
                .copy("ECToolbox/H2CVectors/P256_XMD-SHA-256_SSWU_RO_.json"),
                .copy("ECToolbox/H2CVectors/P384_XMD-SHA-384_SSWU_RO_.json"),
                .copy("OPRFs/OPRFVectors/OPRFVectors-RFC9497.json"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(name: "CryptoBoringWrapperTests", dependencies: ["CryptoBoringWrapper"]),
        .testTarget(name: "CXKCPTests", dependencies: ["CXKCP"]),
    ],
    cxxLanguageStandard: .cxx17
)

if includePerformanceValidation {
    package.targets.append(
        .executableTarget(
            name: "crypto-performance-validation",
            dependencies: [
                "CCryptoBoringSSL",
                "Crypto",
            ]
        )
    )
}

package.dependencies += [
    .package(url: "https://github.com/1amageek/swift-asn1.git", branch: "main")
]

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
