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
import SwiftASN1

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
        print("Validating parsing error contracts")
        validateParsingErrorContracts()
        #if !canImport(CryptoKit)
        print("Validating segmented key derivation")
        validateSegmentedKeyDerivation()
        print("Validating ANSI X9.63 key derivation")
        validateANSIKeyAgreementOwnership()
        #endif
        print("Validating hybrid public-key encryption")
        validateHybridPublicKeyEncryption()
        print("Validating finite-field arithmetic")
        validateFiniteFieldArithmetic()
        #if !canImport(CryptoKit)
        print("Validating platform-sized secure storage")
        validateSecureStorageCapacity()
        #endif
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

    private static func validateParsingErrorContracts() {
        do {
            _ = try Curve25519.Signing.PrivateKey(derRepresentation: [0x01, 0x02, 0x03])
            preconditionFailure("Invalid DER unexpectedly produced a private key")
        } catch is ASN1Error {
            // The public API preserves the SwiftASN1 failure on every target.
        } catch {
            preconditionFailure("Invalid DER produced the wrong error type")
        }
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

    #if !canImport(CryptoKit)
    private static func validateSegmentedKeyDerivation() {
        let inputKeyMaterial = SymmetricKey(data: [UInt8](repeating: 0x0b, count: 22))
        let salt = SegmentedValidationBytes(
            firstRegion: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            secondRegion: [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
        )
        let info = SegmentedValidationBytes(
            firstRegion: [0xf0, 0xf1, 0xf2, 0xf3, 0xf4],
            secondRegion: [0xf5, 0xf6, 0xf7, 0xf8, 0xf9]
        )
        let expectedOutput: [UInt8] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ]

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: expectedOutput.count
        )
        derivedKey.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(expectedOutput))
        }

        let contiguousSalt = salt.firstRegion + salt.secondRegion
        let contiguousInfo = info.firstRegion + info.secondRegion
        contiguousSalt.withUnsafeBytes { saltBytes in
            contiguousInfo.withUnsafeBytes { infoBytes in
                let initializedPrefixByteCount = 3
                withUnsafeTemporaryAllocation(
                    byteCount: initializedPrefixByteCount + expectedOutput.count,
                    alignment: 1
                ) { outputBuffer in
                    outputBuffer.initializeMemory(as: UInt8.self, repeating: 0xa5)
                    for index in 0..<initializedPrefixByteCount {
                        outputBuffer[index] = 0x5a
                    }
                    var output = OutputRawSpan(
                        buffer: outputBuffer,
                        initializedCount: initializedPrefixByteCount
                    )
                    HKDF<SHA256>.deriveKey(
                        inputKeyMaterial: inputKeyMaterial,
                        salt: saltBytes.bytes,
                        info: infoBytes.bytes,
                        output: &output
                    )
                    precondition(output.byteCount == outputBuffer.count)
                    precondition(
                        outputBuffer[..<initializedPrefixByteCount]
                            .allSatisfy { $0 == 0x5a }
                    )
                    precondition(
                        outputBuffer[initializedPrefixByteCount...]
                            .elementsEqual(expectedOutput)
                    )
                }

            }
        }

        let extractedKey = HKDF<SHA256>.extract(
            inputKeyMaterial: inputKeyMaterial,
            salt: contiguousSalt
        )
        let expectedExtractedKey = decodeHex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        let rawSpanExtractedKey = contiguousSalt.withUnsafeBytes { saltBytes in
            HKDF<SHA256>.extract(
                inputKeyMaterial: inputKeyMaterial,
                salt: saltBytes.bytes
            )
        }
        precondition(rawSpanExtractedKey == extractedKey)
        precondition(
            extractedKey.byteCount == 32,
            "Unexpected SHA-256 authentication code byte count: \(extractedKey.byteCount)"
        )
        precondition(SHA256.Digest.byteCount == 32)
        extractedKey.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(expectedExtractedKey))
        }
        precondition(extractedKey.elementsEqual(expectedExtractedKey))
        precondition(Array(extractedKey).elementsEqual(expectedExtractedKey))
        let matchingExtractedKey = HKDF<SHA256>.extract(
            inputKeyMaterial: inputKeyMaterial,
            salt: contiguousSalt
        )
        let distinctExtractedKey = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: [UInt8](repeating: 0x0c, count: 22)),
            salt: contiguousSalt
        )
        precondition(extractedKey == matchingExtractedKey)
        precondition(extractedKey != distinctExtractedKey)
        precondition(extractedKey.hashValue == matchingExtractedKey.hashValue)
        #if !hasFeature(Embedded)
        precondition(!extractedKey.description.isEmpty)
        #endif
        let ownedExtractedKey = SymmetricKey(data: extractedKey)
        precondition(ownedExtractedKey.bitCount == SHA256.Digest.byteCount * 8)
        ownedExtractedKey.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(expectedExtractedKey))
        }
        let saltKey = SymmetricKey(data: contiguousSalt)
        inputKeyMaterial.withUnsafeBytes { inputKeyMaterialBytes in
            precondition(
                HMAC<SHA256>.isValidAuthenticationCode(
                    extractedKey,
                    authenticating: inputKeyMaterialBytes,
                    using: saltKey
                )
            )
        }
        precondition(
            !HMAC<SHA256>.isValidAuthenticationCode(
                extractedKey,
                authenticating: Data([0x00]),
                using: saltKey
            )
        )

        extractedKey.withUnsafeBytes { pseudoRandomKeyBytes in
            contiguousInfo.withUnsafeBytes { infoBytes in
                let initializedPrefixByteCount = 3
                withUnsafeTemporaryAllocation(
                    byteCount: initializedPrefixByteCount + expectedOutput.count,
                    alignment: 1
                ) { outputBuffer in
                    outputBuffer.initializeMemory(as: UInt8.self, repeating: 0xa5)
                    for index in 0..<initializedPrefixByteCount {
                        outputBuffer[index] = 0x5a
                    }
                    var output = OutputRawSpan(
                        buffer: outputBuffer,
                        initializedCount: initializedPrefixByteCount
                    )
                    HKDF<SHA256>.expand(
                        pseudoRandomKey: pseudoRandomKeyBytes.bytes,
                        info: infoBytes.bytes,
                        into: &output
                    )
                    precondition(output.byteCount == outputBuffer.count)
                    precondition(
                        outputBuffer[..<initializedPrefixByteCount]
                            .allSatisfy { $0 == 0x5a }
                    )
                    precondition(
                        outputBuffer[initializedPrefixByteCount...]
                            .elementsEqual(expectedOutput)
                    )
                }
            }
        }

        let shortAuthenticationKey = [UInt8](repeating: 0x0b, count: 20)
        let shortAuthenticationMessage = Data("Hi There".utf8)
        let expectedSHA256AuthenticationCode = decodeHex(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        validateAuthenticationCode(
            using: SHA256.self,
            key: shortAuthenticationKey,
            message: shortAuthenticationMessage,
            expectedHex: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        var incrementalAuthenticator = HMAC<SHA256>(
            key: SymmetricKey(data: shortAuthenticationKey)
        )
        incrementalAuthenticator.update(data: Data("Hi ".utf8))
        incrementalAuthenticator.update(data: Data("There".utf8))
        let firstFinalizedAuthenticationCode = incrementalAuthenticator.finalize()
        let secondFinalizedAuthenticationCode = incrementalAuthenticator.finalize()
        firstFinalizedAuthenticationCode.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(expectedSHA256AuthenticationCode))
        }
        precondition(
            secondFinalizedAuthenticationCode == firstFinalizedAuthenticationCode
        )

        let sha384AuthenticationCode = HMAC<SHA384>.authenticationCode(
            for: shortAuthenticationMessage,
            using: SymmetricKey(data: shortAuthenticationKey)
        )
        sha384AuthenticationCode.withUnsafeBytes { bytes in
            precondition(
                bytes.elementsEqual(
                    decodeHex(
                        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
                    )
                )
            )
        }

        let sha512AuthenticationCode = HMAC<SHA512>.authenticationCode(
            for: shortAuthenticationMessage,
            using: SymmetricKey(data: shortAuthenticationKey)
        )
        sha512AuthenticationCode.withUnsafeBytes { bytes in
            precondition(
                bytes.elementsEqual(
                    decodeHex(
                        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
                    )
                )
            )
        }
        let sha512AuthenticationKey = SymmetricKey(data: sha512AuthenticationCode)
        precondition(sha512AuthenticationKey.bitCount == SHA512.Digest.byteCount * 8)

        let sha512256AuthenticationCode = HMAC<SHA512256>.authenticationCode(
            for: shortAuthenticationMessage,
            using: SymmetricKey(data: shortAuthenticationKey)
        )
        sha512256AuthenticationCode.withUnsafeBytes { bytes in
            precondition(
                bytes.elementsEqual(
                    decodeHex("9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab")
                )
            )
        }
        let sha512256AuthenticationKey = SymmetricKey(
            data: sha512256AuthenticationCode
        )
        precondition(
            sha512256AuthenticationKey.bitCount == SHA512256Digest.byteCount * 8
        )

        let longAuthenticationKey = [UInt8](repeating: 0xaa, count: 131)
        let longAuthenticationMessage = Data(
            "Test Using Larger Than Block-Size Key - Hash Key First".utf8
        )
        validateAuthenticationCode(
            using: SHA256.self,
            key: longAuthenticationKey,
            message: longAuthenticationMessage,
            expectedHex: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        )
        validateAuthenticationCode(
            using: SHA384.self,
            key: longAuthenticationKey,
            message: longAuthenticationMessage,
            expectedHex: "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        )
        validateAuthenticationCode(
            using: SHA512.self,
            key: longAuthenticationKey,
            message: longAuthenticationMessage,
            expectedHex: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        )

        let longSalt = (0..<131).map { UInt8(truncatingIfNeeded: $0) }
        let longInfo = (0..<257).map { UInt8(truncatingIfNeeded: $0 &* 17) }
        let segmentedLongSalt = SegmentedValidationBytes(
            firstRegion: Array(longSalt[..<65]),
            secondRegion: Array(longSalt[65...])
        )
        let segmentedLongInfo = SegmentedValidationBytes(
            firstRegion: Array(longInfo[..<128]),
            secondRegion: Array(longInfo[128...])
        )
        let contiguousResult = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: longSalt,
            info: longInfo,
            outputByteCount: 96
        )
        let segmentedResult = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: segmentedLongSalt,
            info: segmentedLongInfo,
            outputByteCount: 96
        )
        precondition(segmentedResult == contiguousResult)

        let maximumOutputByteCount = SHA256.Digest.byteCount * 255
        let maximumLengthKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: maximumOutputByteCount
        )
        maximumLengthKey.withUnsafeBytes { bytes in
            precondition(bytes.count == maximumOutputByteCount)
            precondition(
                bytes.suffix(SHA256.Digest.byteCount).elementsEqual(
                    decodeHex("76a3f78bcffe95fecf91923c22ad6ee64d48a6d1b981d7e523d5c0f22154ee88")
                )
            )
        }

    }

    private static func validateAuthenticationCode<H: HashFunction>(
        using _: H.Type,
        key: [UInt8],
        message: Data,
        expectedHex: String
    ) {
        let authenticationCode = HMAC<H>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        authenticationCode.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(decodeHex(expectedHex)))
        }
    }

    private static func validateANSIKeyDerivation() {
        do {
            var firstPrivateKeyBytes = [UInt8](repeating: 0, count: 32)
            firstPrivateKeyBytes[firstPrivateKeyBytes.index(before: firstPrivateKeyBytes.endIndex)] = 1
            var secondPrivateKeyBytes = [UInt8](repeating: 0, count: 32)
            secondPrivateKeyBytes[secondPrivateKeyBytes.index(before: secondPrivateKeyBytes.endIndex)] = 2

            let firstPrivateKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: firstPrivateKeyBytes
            )
            let secondPrivateKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: secondPrivateKeyBytes
            )
            let sharedSecret = try firstPrivateKey.sharedSecretFromKeyAgreement(
                with: secondPrivateKey.publicKey
            )
            let sharedInfo = SegmentedValidationBytes(
                firstRegion: decodeHex("75eef81aa3041e33"),
                secondRegion: decodeHex("b80971203d2c0c52")
            )
            let expectedOutput = decodeHex(
                "d3b8565734d5d644eb2993dd0112f805f40780f0a7c34af94dc8116811d6e1afa0966c288535cc75b7009fd55bdcd00f0b393907c035a4a276393c16827cd26265eb23ac907434b21c6efdc7816d1a21c5d34a2e4ebd08b06ddc94af467032c19a01049273106fdb57e3b1b9e68c7bf8d86bf5c19f57fa81e236575f590a1c7e"
            )
            let outputByteCount = 113
            let derivedKey = sharedSecret.x963DerivedSymmetricKey(
                using: SHA256.self,
                sharedInfo: sharedInfo,
                outputByteCount: outputByteCount
            )
            derivedKey.withUnsafeBytes { bytes in
                precondition(bytes.count == outputByteCount)
                precondition(bytes.elementsEqual(expectedOutput.prefix(outputByteCount)))
            }
        } catch {
            preconditionFailure("ANSI X9.63 capability validation failed")
        }
    }

    private static func validateANSIKeyAgreementOwnership() {
        do {
            var firstPrivateKeyBytes = [UInt8](repeating: 0, count: 32)
            firstPrivateKeyBytes[firstPrivateKeyBytes.index(before: firstPrivateKeyBytes.endIndex)] = 1
            let firstPrivateKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: firstPrivateKeyBytes
            )
            firstPrivateKey.rawRepresentation.withUnsafeBytes { bytes in
                precondition(bytes.count == 32)
            }
        } catch {
            preconditionFailure("ANSI X9.63 key agreement validation failed")
        }
    }
    #endif

    private static func validateHybridPublicKeyEncryption() {
        do {
            let recipientKey = Curve25519.KeyAgreement.PrivateKey()
            let info = Data([0x10, 0x20, 0x30])
            let plaintext = Data([0x40, 0x50, 0x60, 0x70])
            let authenticatedData = Data([0x80, 0x90])
            var sender = try HPKE.Sender(
                recipientKey: recipientKey.publicKey,
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: info
            )
            var recipient = try HPKE.Recipient(
                privateKey: recipientKey,
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: info,
                encapsulatedKey: sender.encapsulatedKey
            )
            let ciphertext = try sender.seal(plaintext, authenticating: authenticatedData)
            let recovered = try recipient.open(ciphertext, authenticating: authenticatedData)
            precondition(recovered == plaintext)

            let maximumExportByteCount = SHA256.Digest.byteCount * 255
            let maximumSenderSecret = try sender.exportSecret(
                context: Data(),
                outputByteCount: maximumExportByteCount
            )
            precondition(maximumSenderSecret.bitCount == maximumExportByteCount * 8)
            let maximumRecipientSecret = try recipient.exportSecret(
                context: Data(),
                outputByteCount: maximumExportByteCount
            )
            precondition(maximumRecipientSecret == maximumSenderSecret)

            #if !canImport(CryptoKit)
            let xWingPrivateKey = try XWingMLKEM768X25519.PrivateKey.generate()
            let integrityCheckedRepresentation = xWingPrivateKey.integrityCheckedRepresentation
            let splitIndex = 17
            let segmentedRepresentation = SegmentedValidationBytes(
                firstRegion: Array(integrityCheckedRepresentation[..<splitIndex]),
                secondRegion: Array(integrityCheckedRepresentation[splitIndex...])
            )
            let recoveredXWingPrivateKey = try XWingMLKEM768X25519.PrivateKey(
                integrityCheckedRepresentation: segmentedRepresentation
            )
            precondition(
                recoveredXWingPrivateKey.integrityCheckedRepresentation
                    == integrityCheckedRepresentation
            )
            try validateGeneratedDiffieHellmanHPKERoundTrip(
                recipientKey: P256.KeyAgreement.PrivateKey(),
                ciphersuite: .P256_SHA256_AES_GCM_256
            )
            try validateGeneratedDiffieHellmanHPKERoundTrip(
                recipientKey: P384.KeyAgreement.PrivateKey(),
                ciphersuite: .P384_SHA384_AES_GCM_256
            )
            try validateGeneratedDiffieHellmanHPKERoundTrip(
                recipientKey: P521.KeyAgreement.PrivateKey(),
                ciphersuite: .P521_SHA512_AES_GCM_256
            )
            try validateGeneratedKEMHPKERoundTrip(
                recipientKey: recoveredXWingPrivateKey,
                ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256
            )
            requireHPKEError(.ciphertextTooShort) { () throws(CryptoKitMetaError) -> Data in
                try recipient.open(Data())
            }
            try validateHPKEErrorContracts()
            #endif

            try validateBaseHPKEVector()
            try validateP521HPKEVector()
            try validatePresharedKeyHPKEVector()
            try validateAuthenticatedHPKEVector()
            try validateAuthenticatedPresharedKeyHPKEVector()
        } catch {
            preconditionFailure("HPKE capability validation failed")
        }
    }

    private static func validateBaseHPKEVector() throws(CryptoKitMetaError) {
        let recipientKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(
                decodeHex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
            )
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(decodeHex("4f6465206f6e2061204772656369616e2055726e")),
            encapsulatedKey: Data(
                decodeHex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
            )
        )
        try validateHPKEVectorResult(
            recipient: &recipient,
            exportedSecret: "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
            ciphertext: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
            authenticatedData: "436f756e742d30",
            plaintext: "4265617574792069732074727574682c20747275746820626561757479"
        )

        #if !canImport(CryptoKit)
            let segmentedExportContext = SegmentedValidationBytes(
                firstRegion: decodeHex("5465737443"),
                secondRegion: decodeHex("6f6e74657874")
            )
            let segmentedExport = try recipient.exportSecret(
                context: segmentedExportContext,
                outputByteCount: 32
            )
            segmentedExport.withUnsafeBytes { bytes in
                precondition(
                    bytes.elementsEqual(
                        decodeHex(
                            "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"
                        )
                    )
                )
            }
        #endif

        let maximumOutputByteCount = SHA256.Digest.byteCount * 255
        let maximumExport = try recipient.exportSecret(
            context: Data(),
            outputByteCount: maximumOutputByteCount
        )
        maximumExport.withUnsafeBytes { bytes in
            precondition(bytes.count == maximumOutputByteCount)
            precondition(
                bytes.suffix(SHA256.Digest.byteCount).elementsEqual(
                    decodeHex(
                        "6b8581daf76257d35c046bdbc224dac64d161bcd7ab1280c8144a6708d2149e3"
                    )
                )
            )
        }

        let secondPlaintext = try recipient.open(
            Data(
                decodeHex(
                    "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"
                )
            ),
            authenticating: Data(decodeHex("436f756e742d31"))
        )
        precondition(
            secondPlaintext.elementsEqual(
                decodeHex("4265617574792069732074727574682c20747275746820626561757479")
            )
        )
    }

    private static func validateP521HPKEVector() throws(CryptoKitMetaError) {
        let recipientKey = try P521.KeyAgreement.PrivateKey(
            rawRepresentation: Data(
                decodeHex(
                    "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847"
                )
            )
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: .P521_SHA512_AES_GCM_256,
            info: Data(decodeHex("4f6465206f6e2061204772656369616e2055726e")),
            encapsulatedKey: Data(
                decodeHex(
                    "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
                )
            )
        )
        try validateHPKEVectorResult(
            recipient: &recipient,
            exportedSecret: "05e2e5bd9f0c30832b80a279ff211cc65eceb0d97001524085d609ead60d0412",
            ciphertext: "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
            authenticatedData: "436f756e742d30",
            plaintext: "4265617574792069732074727574682c20747275746820626561757479"
        )
    }

    private static func validatePresharedKeyHPKEVector() throws(CryptoKitMetaError) {
        let recipientKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(
                decodeHex("77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879")
            )
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(decodeHex("4f6465206f6e2061204772656369616e2055726e")),
            encapsulatedKey: Data(
                decodeHex("2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04")
            ),
            presharedKey: SymmetricKey(
                data: decodeHex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
            ),
            presharedKeyIdentifier: Data(
                decodeHex("456e6e796e20447572696e206172616e204d6f726961")
            )
        )
        try validateHPKEVectorResult(
            recipient: &recipient,
            exportedSecret: "813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40",
            ciphertext: "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff",
            authenticatedData: "436f756e742d30",
            plaintext: "4265617574792069732074727574682c20747275746820626561757479"
        )
    }

    private static func validateAuthenticatedHPKEVector() throws(CryptoKitMetaError) {
        let recipientKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(
                decodeHex("3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82")
            )
        )
        let senderKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(
                decodeHex("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b")
            )
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(decodeHex("4f6465206f6e2061204772656369616e2055726e")),
            encapsulatedKey: Data(
                decodeHex("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e")
            ),
            authenticatedBy: senderKey
        )
        try validateHPKEVectorResult(
            recipient: &recipient,
            exportedSecret: "070cffafd89b67b7f0eeb800235303a223e6ff9d1e774dce8eac585c8688c872",
            ciphertext: "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf",
            authenticatedData: "436f756e742d30",
            plaintext: "4265617574792069732074727574682c20747275746820626561757479"
        )
    }

    private static func validateAuthenticatedPresharedKeyHPKEVector() throws(CryptoKitMetaError) {
        let recipientKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(
                decodeHex("7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c")
            )
        )
        let senderKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(
                decodeHex("3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45")
            )
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(decodeHex("4f6465206f6e2061204772656369616e2055726e")),
            encapsulatedKey: Data(
                decodeHex("656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02")
            ),
            authenticatedBy: senderKey,
            presharedKey: SymmetricKey(
                data: decodeHex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
            ),
            presharedKeyIdentifier: Data(
                decodeHex("456e6e796e20447572696e206172616e204d6f726961")
            )
        )
        try validateHPKEVectorResult(
            recipient: &recipient,
            exportedSecret: "c23ebd4e7a0ad06a5dddf779f65004ce9481069ce0f0e6dd51a04539ddcbd5cd",
            ciphertext: "9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597",
            authenticatedData: "436f756e742d30",
            plaintext: "4265617574792069732074727574682c20747275746820626561757479"
        )
    }

    private static func validateHPKEVectorResult(
        recipient: inout HPKE.Recipient,
        exportedSecret: String,
        ciphertext: String,
        authenticatedData: String,
        plaintext: String
    ) throws(CryptoKitMetaError) {
        let actualExportedSecret: SymmetricKey
        do {
            actualExportedSecret = try recipient.exportSecret(
                context: Data(),
                outputByteCount: 32
            )
        } catch {
            preconditionFailure("HPKE rejected a valid export length")
        }
        actualExportedSecret.withUnsafeBytes { bytes in
            precondition(bytes.elementsEqual(decodeHex(exportedSecret)))
        }
        let actualPlaintext = try recipient.open(
            Data(decodeHex(ciphertext)),
            authenticating: Data(decodeHex(authenticatedData))
        )
        precondition(actualPlaintext.elementsEqual(decodeHex(plaintext)))
    }

    #if !canImport(CryptoKit)
    private static func validateGeneratedDiffieHellmanHPKERoundTrip<PrivateKey>(
        recipientKey: PrivateKey,
        ciphersuite: HPKE.Ciphersuite
    ) throws(CryptoKitMetaError) where PrivateKey: HPKEDiffieHellmanPrivateKey {
        var sender = try HPKE.Sender(
            recipientKey: recipientKey.publicKey,
            ciphersuite: ciphersuite,
            info: Data([0x01, 0x02, 0x03])
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: ciphersuite,
            info: Data([0x01, 0x02, 0x03]),
            encapsulatedKey: sender.encapsulatedKey
        )
        try validateGeneratedHPKEContexts(sender: &sender, recipient: &recipient)
    }

    private static func validateGeneratedKEMHPKERoundTrip<PrivateKey>(
        recipientKey: PrivateKey,
        ciphersuite: HPKE.Ciphersuite
    ) throws(CryptoKitMetaError) where PrivateKey: HPKEKEMPrivateKey {
        var sender = try HPKE.Sender(
            recipientKey: recipientKey.publicKey,
            ciphersuite: ciphersuite,
            info: Data([0x01, 0x02, 0x03])
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: ciphersuite,
            info: Data([0x01, 0x02, 0x03]),
            encapsulatedKey: sender.encapsulatedKey
        )
        try validateGeneratedHPKEContexts(sender: &sender, recipient: &recipient)
    }

    private static func validateGeneratedHPKEContexts(
        sender: inout HPKE.Sender,
        recipient: inout HPKE.Recipient
    ) throws(CryptoKitMetaError) {
        let authenticatedData = Data([0x04, 0x05])
        let plaintext = Data([0x06, 0x07, 0x08, 0x09])
        let ciphertext = try sender.seal(
            plaintext,
            authenticating: authenticatedData
        )
        let recovered = try recipient.open(
            ciphertext,
            authenticating: authenticatedData
        )
        precondition(recovered == plaintext)

        let senderSecret = try sender.exportSecret(
            context: Data([0x0a]),
            outputByteCount: 64
        )
        let recipientSecret = try recipient.exportSecret(
            context: Data([0x0a]),
            outputByteCount: 64
        )
        precondition(senderSecret == recipientSecret)
    }

    private static func validateHPKEErrorContracts() throws(CryptoKitMetaError) {
        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let exportOnlyCiphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .exportOnly
        )
        var sender = try HPKE.Sender(
            recipientKey: recipientKey.publicKey,
            ciphersuite: exportOnlyCiphersuite,
            info: Data()
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: exportOnlyCiphersuite,
            info: Data(),
            encapsulatedKey: sender.encapsulatedKey
        )
        let senderSecret = try sender.exportSecret(
            context: Data(),
            outputByteCount: 32
        )
        let recipientSecret = try recipient.exportSecret(
            context: Data(),
            outputByteCount: 32
        )
        precondition(senderSecret == recipientSecret)

        requireHPKEError(.exportOnlyMode) { () throws(CryptoKitMetaError) -> Data in
            try sender.seal(Data())
        }
        requireHPKEError(.exportOnlyMode) { () throws(CryptoKitMetaError) -> Data in
            try recipient.open(Data())
        }

        let p256RecipientKey = P256.KeyAgreement.PrivateKey()
        requireHPKEError(.inconsistentCiphersuiteAndKey) { () throws(CryptoKitMetaError) -> HPKE.Sender in
            try HPKE.Sender(
                recipientKey: p256RecipientKey.publicKey,
                ciphersuite: .P384_SHA384_AES_GCM_256,
                info: Data()
            )
        }
        requireHPKEError(.inconsistentCiphersuiteAndKey) { () throws(CryptoKitMetaError) -> HPKE.Recipient in
            try HPKE.Recipient(
                privateKey: p256RecipientKey,
                ciphersuite: .P384_SHA384_AES_GCM_256,
                info: Data(),
                encapsulatedKey: Data()
            )
        }

        requireCryptoKitError(.incorrectKeySize) { () throws(CryptoKitMetaError) -> XWingMLKEM768X25519.PrivateKey in
            try XWingMLKEM768X25519.PrivateKey(
                integrityCheckedRepresentation: Data(repeating: 0, count: 63)
            )
        }
        requireCryptoKitError(.incorrectKeySize) { () throws(CryptoKitMetaError) -> XWingMLKEM768X25519.PrivateKey in
            try XWingMLKEM768X25519.PrivateKey(
                integrityCheckedRepresentation: Data(repeating: 0, count: 65)
            )
        }

        let validXWingPrivateKey = try XWingMLKEM768X25519.PrivateKey.generate()
        var corruptedIntegrityCheckedRepresentation =
            validXWingPrivateKey.integrityCheckedRepresentation
        corruptedIntegrityCheckedRepresentation[
            corruptedIntegrityCheckedRepresentation.index(
                before: corruptedIntegrityCheckedRepresentation.endIndex
            )
        ] ^= 1
        requireKEMError(.publicKeyMismatchDuringInitialization) {
            () throws(CryptoKitMetaError) -> XWingMLKEM768X25519.PrivateKey in
            try XWingMLKEM768X25519.PrivateKey(
                integrityCheckedRepresentation: corruptedIntegrityCheckedRepresentation
            )
        }
    }

    private static func requireHPKEError<T>(
        _ expectedError: HPKE.Errors,
        operation: () throws(CryptoKitMetaError) -> T
    ) {
        do {
            _ = try operation()
            preconditionFailure("HPKE operation unexpectedly succeeded")
        } catch {
            precondition(
                isHPKEError(error, expectedError),
                "HPKE operation returned the wrong error"
            )
        }
    }

    private static func requireCryptoKitError<T>(
        _ expectedError: CryptoKitError,
        operation: () throws(CryptoKitMetaError) -> T
    ) {
        do {
            _ = try operation()
            preconditionFailure("Crypto operation unexpectedly succeeded")
        } catch {
            precondition(
                isCryptoKitError(error, expectedError),
                "Crypto operation returned the wrong error"
            )
        }
    }

    private static func requireKEMError<T>(
        _ expectedError: KEM.Errors,
        operation: () throws(CryptoKitMetaError) -> T
    ) {
        do {
            _ = try operation()
            preconditionFailure("KEM operation unexpectedly succeeded")
        } catch {
            precondition(
                isKEMError(error, expectedError),
                "KEM operation returned the wrong error"
            )
        }
    }
    #endif

    private static func decodeHex(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(hex.utf8.count / 2)
        var highNibble: UInt8?

        for character in hex.utf8 {
            let nibble: UInt8
            switch character {
            case 48...57:
                nibble = character - 48
            case 97...102:
                nibble = character - 87
            default:
                preconditionFailure("Invalid hexadecimal validation vector")
            }

            if let high = highNibble {
                result.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }

        precondition(highNibble == nil)
        return result
    }

    private static func isAuthenticationFailure(_ error: CryptoKitMetaError) -> Bool {
        isCryptoKitError(error, .authenticationFailure)
    }

    private static func isCryptoKitError(
        _ error: CryptoKitMetaError,
        _ expectedError: CryptoKitError
    ) -> Bool {
        return (error as? CryptoKitError) == expectedError
    }

    #if !canImport(CryptoKit)
    private static func isHPKEError(
        _ error: CryptoKitMetaError,
        _ expectedError: HPKE.Errors
    ) -> Bool {
        return (error as? HPKE.Errors) == expectedError
    }

    private static func isKEMError(
        _ error: CryptoKitMetaError,
        _ expectedError: KEM.Errors
    ) -> Bool {
        return (error as? KEM.Errors) == expectedError
    }
    #endif

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

    #if !canImport(CryptoKit)
    private static func validateSecureStorageCapacity() {
        precondition(UInt32(0).nextPowerOf2ClampedToMax() == 1)
        precondition(UInt32(3).nextPowerOf2ClampedToMax() == 4)
        precondition(
            UInt32.max.nextPowerOf2ClampedToMax() == UInt32(clamping: Int.max)
        )
    }
    #endif

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
