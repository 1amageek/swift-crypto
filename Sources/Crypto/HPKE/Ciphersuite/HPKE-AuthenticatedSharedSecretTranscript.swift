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

#if canImport(CryptoKit)
import CryptoKit
#else

struct HPKEAuthenticatedSharedSecretTranscript<
    EphemeralSharedSecret: ContiguousBytes,
    AuthenticationSharedSecret: ContiguousBytes
>: HPKETranscript {
    let ephemeralSharedSecret: EphemeralSharedSecret
    let authenticationSharedSecret: AuthenticationSharedSecret

    func forEachByteRegion(_ body: (RawSpan) -> Void) {
        ephemeralSharedSecret.withUnsafeBytes { buffer in
            body(buffer.bytes)
        }
        authenticationSharedSecret.withUnsafeBytes { buffer in
            body(buffer.bytes)
        }
    }
}

#endif // canImport(CryptoKit)
