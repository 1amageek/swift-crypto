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

import Crypto
import CryptoBoringWrapper
import CryptoExtras

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

@main
struct CryptoCapabilityValidationCommand {
    static func main() {
        print("Validating Base64")
        validateBase64()
        print("Validating encryption and entropy")
        validateEncryptionAndEntropy()
        print("Validating authenticated encryption")
        validateAuthenticatedEncryption()
        print("Validating finite-field arithmetic")
        validateFiniteFieldArithmetic()
        #if !canImport(FoundationEssentials) && !canImport(Foundation)
        print("Validating borrowed slices")
        validateBorrowedSlice()
        #endif
        print("Crypto capability validation passed")
    }

    private static func validateBase64() {
        print("Checking empty Base64")
        validateBase64("", expected: [])
        print("Checking one-byte Base64")
        validateBase64("Zg==", expected: [0x66])
        print("Checking two-byte Base64")
        validateBase64("Zm8=", expected: [0x66, 0x6f])
        print("Checking three-byte Base64")
        validateBase64("Zm9v", expected: [0x66, 0x6f, 0x6f])

        #if !canImport(FoundationEssentials) && !canImport(Foundation)
        print("Checking canonical Base64 rejection")
        validateInvalidBase64("A")
        validateInvalidBase64("AA=")
        validateInvalidBase64("AB==")
        validateInvalidBase64("AAB=")
        validateInvalidBase64("AAAA=")
        validateInvalidBase64("AA=A")
        validateInvalidBase64("====")
        validateInvalidBase64("Zm9v\n")
        #endif
    }

    private static func validateBase64(_ encoded: String, expected: [UInt8]) {
        guard let decoded = Data(base64Encoded: encoded) else {
            preconditionFailure("Valid Base64 was rejected")
        }
        precondition(decoded.elementsEqual(expected))
    }

    #if !canImport(FoundationEssentials) && !canImport(Foundation)
    private static func validateInvalidBase64(_ encoded: String) {
        precondition(Data(base64Encoded: encoded) == nil)
    }
    #endif

    private static func validateEncryptionAndEntropy() {
        let key = SymmetricKey(data: [UInt8](repeating: 0x5a, count: 16))
        let plaintext = Data([0x10, 0x20, 0x30, 0x40, 0x50])
        let nonce = AES._CTR.Nonce()

        do {
            let ciphertext = try AES._CTR.encrypt(plaintext, using: key, nonce: nonce)
            let recovered = try AES._CTR.decrypt(ciphertext, using: key, nonce: nonce)
            precondition(recovered == plaintext)
        } catch {
            preconditionFailure("AES-CTR capability validation failed")
        }
    }

    private static func validateAuthenticatedEncryption() {
        let key = SymmetricKey(data: [UInt8](repeating: 0xa5, count: 16))
        let plaintext = Data([0x10, 0x20, 0x30, 0x40, 0x50])
        let authenticatedData = Data([0x60, 0x70, 0x80])
        let firstNonce = AES.GCM._SIV.Nonce()
        let secondNonce = AES.GCM._SIV.Nonce()
        precondition(!firstNonce.elementsEqual(secondNonce))

        do {
            let sealedBox = try AES.GCM._SIV.seal(
                plaintext,
                using: key,
                nonce: firstNonce,
                authenticating: authenticatedData
            )
            let recovered = try AES.GCM._SIV.open(
                sealedBox,
                using: key,
                authenticating: authenticatedData
            )
            precondition(recovered == plaintext)

            var corruptedCombined = sealedBox.combined
            corruptedCombined[corruptedCombined.index(before: corruptedCombined.endIndex)] ^= 1
            let corruptedBox = try AES.GCM._SIV.SealedBox(combined: corruptedCombined)

            do {
                _ = try AES.GCM._SIV.open(
                    corruptedBox,
                    using: key,
                    authenticating: authenticatedData
                )
                preconditionFailure("AES-GCM-SIV accepted a corrupted authentication tag")
            } catch {
                precondition(
                    isAuthenticationFailure(error),
                    "AES-GCM-SIV returned the wrong authentication error"
                )
            }
        } catch {
            preconditionFailure("AES-GCM-SIV capability validation failed")
        }
    }

    private static func isAuthenticationFailure(_ error: CryptoKitMetaError) -> Bool {
        #if hasFeature(Embedded)
        guard case .cryptoKitError(let underlyingError) = error else {
            return false
        }
        return underlyingError == .authenticationFailure
        #else
        return error as? CryptoKitError == .authenticationFailure
        #endif
    }

    private static func validateFiniteFieldArithmetic() {
        do {
            let arithmeticContext = try FiniteFieldArithmeticContext(modulus: 17)

            let sum = try arithmeticContext.add(9, 11)
            precondition(sum == 3)

            let product = try arithmeticContext.multiply(5, 7)
            precondition(product == 1)

            let inverse = try arithmeticContext.inverse(5)
            precondition(inverse == 7)

            let missingInverse = try arithmeticContext.inverse(0)
            precondition(missingInverse == nil)

            let recoveredSum = try arithmeticContext.add(16, 2)
            precondition(recoveredSum == 1)

            do {
                _ = try arithmeticContext.pow(secret: 17, 2)
                preconditionFailure("Finite-field arithmetic accepted an out-of-range secret")
            } catch CryptoBoringWrapperError.incorrectParameterSize {
                let recoveredProduct = try arithmeticContext.multiply(4, 9)
                precondition(recoveredProduct == 2)
            }
        } catch {
            preconditionFailure("Finite-field arithmetic capability validation failed")
        }
    }

    private static func validateBorrowedSlice() {
        let owner = Data([0x00, 0x10, 0x20, 0x30, 0x40])
        var slice = owner[1..<4]
        precondition(slice.startIndex == 1)
        precondition(slice.endIndex == 4)

        owner.withUnsafeBytes { ownerBytes in
            slice.withUnsafeBytes { sliceBytes in
                precondition(sliceBytes.count == 3)
                precondition(
                    sliceBytes.baseAddress == ownerBytes.baseAddress?.advanced(by: 1)
                )
            }
        }

        slice[2] = 0xff
        precondition(owner[2] == 0x20)
        precondition(slice.elementsEqual([0x10, 0xff, 0x30]))
    }
}
