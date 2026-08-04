//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

#if canImport(CryptoKit) && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else

struct HPKEInformationTranscript<Bytes: DataProtocol>: HPKETranscript {
    let bytes: Bytes

    func forEachByteRegion(_ body: (RawSpan) -> Void) {
        for region in bytes.regions {
            region.withUnsafeBytes { buffer in
                body(buffer.bytes)
            }
        }
    }
}

#endif // canImport(CryptoKit)
