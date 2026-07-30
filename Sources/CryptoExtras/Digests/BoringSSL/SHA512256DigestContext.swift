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

internal import CCryptoBoringSSL
import Crypto
import CryptoBoringWrapper

#if canImport(Darwin)
import Darwin
#endif

final class SHA512256DigestContext: Sendable {
    private let state: CryptoMutex<SHA512_CTX>

    init() {
        guard let state = SHA512256DigestOperations.initialize() else {
            preconditionFailure("Unable to initialize digest state")
        }
        self.state = CryptoMutex(state)
    }

    private init(_ state: SHA512_CTX) {
        self.state = CryptoMutex(state)
    }

    func copy() -> SHA512256DigestContext {
        state.withLock { SHA512256DigestContext($0) }
    }

    func update(bufferPointer data: UnsafeRawBufferPointer) {
        let didUpdate = state.withLock { state in
            SHA512256DigestOperations.update(&state, data: data)
        }
        guard didUpdate else {
            preconditionFailure("Unable to update digest state")
        }
    }

    func finalize() -> SHA512256Digest {
        state.withLock { state in
            var finalState = state
            defer {
                zeroizeSHA512State(&finalState)
            }

            return withUnsafeTemporaryAllocation(
                byteCount: SHA512256DigestOperations.digestSize,
                alignment: 1
            ) { digestPointer in
                defer {
                    digestPointer.zeroize()
                }

                guard SHA512256DigestOperations.finalize(
                    &finalState,
                    digest: digestPointer
                ) else {
                    preconditionFailure("Unable to finalize digest state")
                }
                guard let digest = SHA512256Digest(
                    bufferPointer: UnsafeRawBufferPointer(digestPointer)
                ) else {
                    preconditionFailure("Digest size does not match SHA-512/256")
                }
                return digest
            }
        }
    }

    deinit {
        state.withLock { state in
            zeroizeSHA512State(&state)
        }
    }
}

private func zeroizeSHA512State(_ state: inout SHA512_CTX) {
    withUnsafeMutableBytes(of: &state) { bytes in
        bytes.zeroize()
    }
}

extension UnsafeMutableRawBufferPointer {
    fileprivate func zeroize() {
        guard let baseAddress, count > 0 else {
            return
        }
        memset_s(baseAddress, count, 0, count)
    }
}
