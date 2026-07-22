//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(CryptoKit)
import CryptoKit
#else
import CXKCP
import CXKCPShims

extension SHA3_256 {
    static var digestSize: Int { 32 }

    static func makeContext() -> KeccakDigestContext? {
        var state = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_256(&state) == KECCAK_SUCCESS else {
            return nil
        }
        return KeccakDigestContext(state)
    }

    static func copyContext(_ context: KeccakDigestContext) -> KeccakDigestContext {
        context.copy()
    }

    static func update(_ context: KeccakDigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.update(data: data)
    }

    static func finalize(
        _ context: KeccakDigestContext,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == digestSize else {
            return false
        }
        return context.withState { state in
            var finalState = state
            defer {
                withUnsafeMutableBytes(of: &finalState) { $0.zeroize() }
            }
            return Keccak_HashFinal(&finalState, baseAddress) == KECCAK_SUCCESS
        }
    }
}

extension SHA3_384 {
    static var digestSize: Int { 48 }

    static func makeContext() -> KeccakDigestContext? {
        var state = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_384(&state) == KECCAK_SUCCESS else {
            return nil
        }
        return KeccakDigestContext(state)
    }

    static func copyContext(_ context: KeccakDigestContext) -> KeccakDigestContext {
        context.copy()
    }

    static func update(_ context: KeccakDigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.update(data: data)
    }

    static func finalize(
        _ context: KeccakDigestContext,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == digestSize else {
            return false
        }
        return context.withState { state in
            var finalState = state
            defer {
                withUnsafeMutableBytes(of: &finalState) { $0.zeroize() }
            }
            return Keccak_HashFinal(&finalState, baseAddress) == KECCAK_SUCCESS
        }
    }
}

extension SHA3_512 {
    static var digestSize: Int { 64 }

    static func makeContext() -> KeccakDigestContext? {
        var state = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_512(&state) == KECCAK_SUCCESS else {
            return nil
        }
        return KeccakDigestContext(state)
    }

    static func copyContext(_ context: KeccakDigestContext) -> KeccakDigestContext {
        context.copy()
    }

    static func update(_ context: KeccakDigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.update(data: data)
    }

    static func finalize(
        _ context: KeccakDigestContext,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == digestSize else {
            return false
        }
        return context.withState { state in
            var finalState = state
            defer {
                withUnsafeMutableBytes(of: &finalState) { $0.zeroize() }
            }
            return Keccak_HashFinal(&finalState, baseAddress) == KECCAK_SUCCESS
        }
    }
}
#endif  // canImport(CryptoKit)
