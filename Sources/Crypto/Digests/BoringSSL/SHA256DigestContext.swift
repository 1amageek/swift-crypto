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
import Synchronization
internal import CCryptoBoringSSL

/// Owns one SHA-256 state with scoped, synchronized access.
final class SHA256DigestContext: Sendable {
    private let state: Mutex<SHA256_CTX>

    init(_ state: SHA256_CTX) {
        self.state = Mutex(state)
    }

    func copy() -> SHA256DigestContext {
        state.withLock { SHA256DigestContext($0) }
    }

    func withState(_ body: (inout SHA256_CTX) -> Bool) -> Bool {
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
