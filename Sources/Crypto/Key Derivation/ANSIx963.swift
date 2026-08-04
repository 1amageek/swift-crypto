//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif


#if canImport(CryptoKit) && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else


internal struct ANSIKDFx963<H: HashFunction>: Sendable {
    public static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey, info: Info, outputByteCount: Int) -> SymmetricKey {
        precondition(H.Digest.byteCount > 0)
        precondition(outputByteCount >= 0)
        let maximumOutputByteCount = UInt64(H.Digest.byteCount) * UInt64(UInt32.max)
        precondition(UInt64(outputByteCount) <= maximumOutputByteCount)

        // Build into owned secure storage so the result outlives every borrowed
        // digest. SymmetricKey reuses the copy-on-write backing without copying.
        var key = SecureBytes()
        key.reserveCapacity(outputByteCount)
        var counter = UInt32(1)

        while key.count < outputByteCount {
            // 1. Compute: Ki = Hash(Z || Counter || [SharedInfo]).
            var hasher = H()
            inputKeyMaterial.withUnsafeBytes { inputKeyMaterialBytes in
                hasher.update(bytes: inputKeyMaterialBytes.bytes)
            }
            hasher.update(counter.bigEndian)
            hasher.update(data: info)
            let digest = hasher.finalize()

            // Append only the requested prefix of the final digest.
            let remainingByteCount = outputByteCount - key.count
            let digestByteCount = min(remainingByteCount, H.Digest.byteCount)
            digest.withUnsafeBytes { digestBytes in
                key.append(
                    digestBytes.bytes.extracting(first: digestByteCount)
                )
            }

            // 2. Increment Counter when another digest block is needed.
            if key.count < outputByteCount {
                counter += 1
            }
        }

        precondition(key.count == outputByteCount)
        return SymmetricKey(data: key)
    }
    
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, info: [UInt8](), outputByteCount: outputByteCount)
    }
}


#endif
