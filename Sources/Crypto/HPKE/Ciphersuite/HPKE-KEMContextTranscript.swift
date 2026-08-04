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

struct HPKEKEMContextTranscript: HPKETranscript {
    let encapsulatedKey: Data
    let recipientPublicKey: Data
    let senderPublicKey: Data?

    func forEachByteRegion(_ body: (RawSpan) -> Void) {
        encapsulatedKey.withUnsafeBytes { buffer in
            body(buffer.bytes)
        }
        recipientPublicKey.withUnsafeBytes { buffer in
            body(buffer.bytes)
        }
        if let senderPublicKey {
            senderPublicKey.withUnsafeBytes { buffer in
                body(buffer.bytes)
            }
        }
    }
}

#endif // canImport(CryptoKit)
