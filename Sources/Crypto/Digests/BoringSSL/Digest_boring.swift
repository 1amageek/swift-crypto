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
internal import CCryptoBoringSSL

extension Insecure.MD5 {
    static var digestSize: Int {
        Int(MD5_DIGEST_LENGTH)
    }

    static func makeContext() -> MD5DigestContext? {
        var state = MD5_CTX()
        guard CCryptoBoringSSL_MD5_Init(&state) == 1 else {
            return nil
        }
        return MD5DigestContext(state)
    }

    static func copyContext(_ context: MD5DigestContext) -> MD5DigestContext {
        context.copy()
    }

    static func update(_ context: MD5DigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.withState { state in
            CCryptoBoringSSL_MD5_Update(&state, data.baseAddress, data.count) == 1
        }
    }

    static func finalize(
        _ context: MD5DigestContext,
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
            return CCryptoBoringSSL_MD5_Final(baseAddress, &finalState) == 1
        }
    }
}

extension Insecure.SHA1 {
    static var digestSize: Int {
        Int(SHA_DIGEST_LENGTH)
    }

    static func makeContext() -> SHA1DigestContext? {
        var state = SHA_CTX()
        guard CCryptoBoringSSL_SHA1_Init(&state) == 1 else {
            return nil
        }
        return SHA1DigestContext(state)
    }

    static func copyContext(_ context: SHA1DigestContext) -> SHA1DigestContext {
        context.copy()
    }

    static func update(_ context: SHA1DigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.withState { state in
            CCryptoBoringSSL_SHA1_Update(&state, data.baseAddress, data.count) == 1
        }
    }

    static func finalize(
        _ context: SHA1DigestContext,
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
            return CCryptoBoringSSL_SHA1_Final(baseAddress, &finalState) == 1
        }
    }
}

extension SHA384 {
    static var digestSize: Int {
        Int(SHA384_DIGEST_LENGTH)
    }

    static func makeContext() -> SHA512FamilyDigestContext? {
        var state = SHA512_CTX()
        guard CCryptoBoringSSL_SHA384_Init(&state) == 1 else {
            return nil
        }
        return SHA512FamilyDigestContext(state)
    }

    static func copyContext(_ context: SHA512FamilyDigestContext) -> SHA512FamilyDigestContext {
        context.copy()
    }

    static func update(_ context: SHA512FamilyDigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.withState { state in
            CCryptoBoringSSL_SHA384_Update(&state, data.baseAddress, data.count) == 1
        }
    }

    static func finalize(
        _ context: SHA512FamilyDigestContext,
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
            return CCryptoBoringSSL_SHA384_Final(baseAddress, &finalState) == 1
        }
    }
}

extension SHA512 {
    static var digestSize: Int {
        Int(SHA512_DIGEST_LENGTH)
    }

    static func makeContext() -> SHA512FamilyDigestContext? {
        var state = SHA512_CTX()
        guard CCryptoBoringSSL_SHA512_Init(&state) == 1 else {
            return nil
        }
        return SHA512FamilyDigestContext(state)
    }

    static func copyContext(_ context: SHA512FamilyDigestContext) -> SHA512FamilyDigestContext {
        context.copy()
    }

    static func update(_ context: SHA512FamilyDigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.withState { state in
            CCryptoBoringSSL_SHA512_Update(&state, data.baseAddress, data.count) == 1
        }
    }

    static func finalize(
        _ context: SHA512FamilyDigestContext,
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
            return CCryptoBoringSSL_SHA512_Final(baseAddress, &finalState) == 1
        }
    }
}
#endif  // canImport(CryptoKit)
