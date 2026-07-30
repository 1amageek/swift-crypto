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

/// Owns one MD5 state with scoped, synchronized access.
///
/// This concrete class intentionally stores the imported C value outside a
/// generic class. Swift 6.4 WASI can corrupt generic class release metadata
/// when a generic field is instantiated with this C context.
final class MD5DigestContext: Sendable {
    private let state: CryptoMutex<MD5_CTX>

    init(_ state: MD5_CTX) {
        self.state = CryptoMutex(state)
    }

    func copy() -> MD5DigestContext {
        state.withLock { MD5DigestContext($0) }
    }

    func withState(_ body: (inout MD5_CTX) -> Bool) -> Bool {
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
