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
enum AESCFBCipher {
    @usableFromInline
    enum Mode {
        case encrypt
        case decrypt

        @usableFromInline
        var encryptionDirection: Int32 {
            switch self {
            case .encrypt: return AES_ENCRYPT
            case .decrypt: return AES_DECRYPT
            }
        }
    }

    @usableFromInline
    static func encryptOrDecrypt<Plaintext: DataProtocol>(
        _ mode: Mode,
        _ plaintext: Plaintext,
        using key: SymmetricKey,
        iv: AES._CFB.IV
    ) throws(CryptoKitMetaError) -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw cryptoExtrasError(CryptoKitError.incorrectKeySize)
        }

        var ciphertext = Data(repeating: 0, count: plaintext.count)
        ciphertext.withUnsafeMutableBytes { ciphertextBufferPtr in
            var iv = iv
            var num = UInt32.zero
            var outputOffset = 0
            key.withUnsafeBytes { keyBufferPtr in
                iv.withUnsafeMutableBytes { ivBufferPtr in
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
                            CCryptoBoringSSL_AES_cfb128_encrypt(
                                plaintextBufferPtr.baseAddress,
                                ciphertextBufferPtr.baseAddress?.advanced(by: outputOffset),
                                plaintextBufferPtr.count,
                                &key,
                                ivBufferPtr.baseAddress,
                                &num,
                                mode.encryptionDirection
                            )
                            outputOffset += plaintextBufferPtr.count
                        }
                    }
                    precondition(outputOffset == ciphertextBufferPtr.count)
                }
            }
        }
        return ciphertext
    }
}
