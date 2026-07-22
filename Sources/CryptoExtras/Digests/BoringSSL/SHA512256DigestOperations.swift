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

struct SHA512256DigestOperations {
    static var digestSize: Int {
        Int(SHA256_DIGEST_LENGTH)
    }

    static func initialize() -> SHA512_CTX? {
        var state = SHA512_CTX()
        guard CCryptoBoringSSL_SHA512_256_Init(&state) == 1 else {
            return nil
        }
        return state
    }

    static func update(_ state: inout SHA512_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_SHA512_256_Update(&state, data.baseAddress, data.count) == 1
    }

    static func finalize(
        _ state: inout SHA512_CTX,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == digestSize else {
            return false
        }
        return CCryptoBoringSSL_SHA512_256_Final(baseAddress, &state) == 1
    }
}
