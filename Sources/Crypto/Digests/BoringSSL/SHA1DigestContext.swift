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

#if !canImport(CryptoKit)
internal import CCryptoBoringSSL
import CryptoBoringWrapper

/// Owns one SHA-1 state with scoped, synchronized access.
final class SHA1DigestContext: Sendable {
    private let state: CryptoMutex<SHA_CTX>

    init(_ state: SHA_CTX) {
        self.state = CryptoMutex(state)
    }

    func copy() -> SHA1DigestContext {
        state.withLock { SHA1DigestContext($0) }
    }

    func withState(_ body: (inout SHA_CTX) -> Bool) -> Bool {
        state.withLock { state in
            body(&state)
        }
    }

    deinit {
        state.withLock { state in
            withUnsafeMutableBytes(of: &state) { $0.zeroize() }
        }
    }
}
#endif
