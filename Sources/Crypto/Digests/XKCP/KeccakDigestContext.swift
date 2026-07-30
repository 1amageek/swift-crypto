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
import CryptoBoringWrapper

/// Owns one Keccak state with scoped, synchronized access.
final class KeccakDigestContext: Sendable {
    private let state: CryptoMutex<Keccak_HashInstance>

    init(_ state: Keccak_HashInstance) {
        self.state = CryptoMutex(state)
    }

    func copy() -> KeccakDigestContext {
        state.withLock { KeccakDigestContext($0) }
    }

    func withState(_ body: (inout Keccak_HashInstance) -> Bool) -> Bool {
        state.withLock { state in
            body(&state)
        }
    }

    func update(
        data: UnsafeRawBufferPointer,
        maximumChunkByteCount: Int = Int.max / 8
    ) -> Bool {
        state.withLock { state in
            forEachKeccakInputChunk(
                data,
                maximumChunkByteCount: maximumChunkByteCount
            ) { chunk in
                guard let baseAddress = chunk.baseAddress else {
                    return true
                }
                return Keccak_HashUpdate(
                    &state,
                    baseAddress,
                    chunk.count * 8
                ) == KECCAK_SUCCESS
            }
        }
    }

    deinit {
        state.withLock { state in
            withUnsafeMutableBytes(of: &state) { $0.zeroize() }
        }
    }
}

package func forEachKeccakInputChunk(
    _ input: UnsafeRawBufferPointer,
    maximumChunkByteCount: Int = Int.max / 8,
    _ body: (UnsafeRawBufferPointer) -> Bool
) -> Bool {
    guard maximumChunkByteCount > 0, maximumChunkByteCount <= Int.max / 8 else {
        return false
    }

    var offset = 0
    while offset < input.count {
        let chunkByteCount = min(maximumChunkByteCount, input.count - offset)
        let end = offset + chunkByteCount
        let chunk = UnsafeRawBufferPointer(rebasing: input[offset..<end])
        guard body(chunk) else {
            return false
        }
        offset = end
    }
    return true
}
#endif
