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
import CXKCP
import Synchronization

/// Owns one Keccak state with scoped, synchronized access.
final class KeccakDigestContext: Sendable {
    private let state: Mutex<Keccak_HashInstance>

    init(_ state: Keccak_HashInstance) {
        self.state = Mutex(state)
    }

    func copy() -> KeccakDigestContext {
        state.withLock { KeccakDigestContext($0) }
    }

    func withState(_ body: (inout Keccak_HashInstance) -> Bool) -> Bool {
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
