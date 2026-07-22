//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if !canImport(CryptoKit)
import Synchronization
internal import CCryptoBoringSSL

/// Owns one SHA-384 or SHA-512 state with scoped, synchronized access.
final class SHA512FamilyDigestContext: Sendable {
    private let state: Mutex<SHA512_CTX>

    init(_ state: SHA512_CTX) {
        self.state = Mutex(state)
    }

    func copy() -> SHA512FamilyDigestContext {
        state.withLock { SHA512FamilyDigestContext($0) }
    }

    func withState(_ body: (inout SHA512_CTX) -> Bool) -> Bool {
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
