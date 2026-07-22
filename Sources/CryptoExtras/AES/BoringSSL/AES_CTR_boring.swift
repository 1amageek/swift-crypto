//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

@usableFromInline
enum AESCTRCipher {
    @usableFromInline
    static func encrypt<Plaintext: DataProtocol>(
        _ plaintext: Plaintext,
        using key: SymmetricKey,
        nonce: AES._CTR.Nonce
    ) throws(CryptoKitMetaError) -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw cryptoExtrasError(CryptoKitError.incorrectKeySize)
        }

        var ciphertext = Data(repeating: 0, count: plaintext.count)
        ciphertext.withUnsafeMutableBytes { ciphertextBufferPtr in
            var nonce = nonce
            var ecountBytes = (Int64.zero, Int64.zero)
            var num = UInt32.zero
            var outputOffset = 0
            key.withUnsafeBytes { keyBufferPtr in
                nonce.withUnsafeMutableBytes { nonceBufferPtr in
                    withUnsafeMutableBytes(of: &ecountBytes) { ecountBufferPtr in
                        var key = AES_KEY()
                        defer {
                            withUnsafeMutableBytes(of: &key) { bytes in
                                guard let baseAddress = bytes.baseAddress else {
                                    return
                                }
                                CCryptoBoringSSL_OPENSSL_cleanse(baseAddress, bytes.count)
                            }
                        }
                        precondition(
                            CCryptoBoringSSL_AES_set_encrypt_key(
                                keyBufferPtr.baseAddress,
                                UInt32(keyBufferPtr.count * 8),
                                &key
                            ) == 0
                        )

                        for region in plaintext.regions {
                            region.withUnsafeBytes { plaintextBufferPtr in
                                guard !plaintextBufferPtr.isEmpty else {
                                    return
                                }

                                precondition(outputOffset <= ciphertextBufferPtr.count - plaintextBufferPtr.count)
                                CCryptoBoringSSL_AES_ctr128_encrypt(
                                    plaintextBufferPtr.baseAddress,
                                    ciphertextBufferPtr.baseAddress?.advanced(by: outputOffset),
                                    plaintextBufferPtr.count,
                                    &key,
                                    nonceBufferPtr.baseAddress,
                                    ecountBufferPtr.baseAddress,
                                    &num
                                )
                                outputOffset += plaintextBufferPtr.count
                            }
                        }
                        precondition(outputOffset == ciphertextBufferPtr.count)
                    }
                }
            }
        }
        return ciphertext
    }
}
