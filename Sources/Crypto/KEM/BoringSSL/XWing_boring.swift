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


#if canImport(CryptoKit)
@_exported import CryptoKit
#else
#if hasFeature(Embedded)
import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLXWingPublicKeyImpl: Sendable {
    private var publicKeyBytes: Data

    fileprivate init(publicKeyBytes: Data) {
        self.publicKeyBytes = publicKeyBytes
    }

    init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
        let rawRepresentation = cryptoData(rawRepresentation)
        guard rawRepresentation.count == XWING_PUBLIC_KEY_BYTES else {
            throw error(CryptoKitError.incorrectKeySize)
        }
        self.publicKeyBytes = rawRepresentation
    }

    var rawRepresentation: Data {
        self.publicKeyBytes
    }

    func encapsulate() throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
        try self.encapsulateWithOptionalEntropy(entropy: nil)
    }

    func encapsulateWithOptionalEntropy(entropy: [UInt8]?) throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
        let (sharedSecretData, encapsulatedSecret, rc): (Data, Data, CInt) = self.publicKeyBytes.withUnsafeBytes { publicKeyBuffer in
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_CIPHERTEXT_BYTES), alignment: 1) {
                ciphertextBuffer in
                withUnsafeTemporaryAllocation(byteCount: Int(XWING_SHARED_SECRET_BYTES), alignment: 1) {
                    sharedSecretBuffer in
                    let rc: CInt
                    if let entropy {
                        rc = CCryptoBoringSSL_XWING_encap_external_entropy(
                            ciphertextBuffer.baseAddress,
                            sharedSecretBuffer.baseAddress,
                            publicKeyBuffer.baseAddress,
                            entropy
                        )
                    } else {
                        rc = CCryptoBoringSSL_XWING_encap(
                            ciphertextBuffer.baseAddress,
                            sharedSecretBuffer.baseAddress,
                            publicKeyBuffer.baseAddress
                        )
                    }
                    return (Data(sharedSecretBuffer), Data(ciphertextBuffer), rc)
                }
            }
        }
        guard rc == 1 else {
            throw error(CryptoKitError.internalBoringSSLError())
        }

        return .init(sharedSecret: SymmetricKey(data: sharedSecretData), encapsulated: encapsulatedSecret)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLXWingPrivateKeyImpl: Sendable {
    private var backing: Backing

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    var integrityCheckedRepresentation: Data {
        self.backing.integrityCheckedRepresentation
    }

    init<D: ContiguousBytes>(bytes: D) throws(CryptoKitMetaError) {
        self.backing = try .init(bytes: cryptoData(bytes))
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws(CryptoKitMetaError) {
        self.backing = try .init(seedRepresentation: Data(seedRepresentation), publicKeyHash: publicKeyHash)
    }

    private init(_ backing: Backing) {
        self.backing = backing
    }

    var dataRepresentation: Data {
        self.backing.dataRepresentation
    }

    static func generate() throws(CryptoKitMetaError) -> Self {
        try Self(.generate())
    }

    func decapsulate(_ encapsulated: Data) throws(CryptoKitMetaError) -> SymmetricKey {
        try self.backing.decapsulate(encapsulated)
    }

    var publicKey: OpenSSLXWingPublicKeyImpl {
        OpenSSLXWingPublicKeyImpl(publicKeyBytes: self.backing.publicKey)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OpenSSLXWingPrivateKeyImpl {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    final class Backing: @unchecked Sendable {
        private var privateKey: XWING_private_key

        init(privateKey: XWING_private_key) {
            self.privateKey = privateKey
        }

        init() throws(CryptoKitMetaError) {
            self.privateKey = .init()
            let rc = withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_generate_key($0.baseAddress, &self.privateKey)
                return rc
            }
            if rc != 1 {
                throw error(CryptoKitError.internalBoringSSLError())
            }
        }

        init(bytes: Data) throws(CryptoKitMetaError) {
            self.privateKey = .init()

            // The first bytes are the private key (in "seed representation"), the latter bytes are the public key.
            let parsed = bytes.withUnsafeBytes { ptr in
                guard ptr.count == Int(XWING_PRIVATE_KEY_BYTES) + Int(XWING_PUBLIC_KEY_BYTES) else {
                    return false
                }
                let privateKeyBytes = UnsafeRawBufferPointer(rebasing: ptr.prefix(Int(XWING_PRIVATE_KEY_BYTES)))
                let publicKeyBytes = UnsafeRawBufferPointer(rebasing: ptr.suffix(Int(XWING_PUBLIC_KEY_BYTES)))

                var cbs = CBS()
                CCryptoBoringSSL_CBS_init(&cbs, privateKeyBytes.baseAddress, privateKeyBytes.count)

                let rc = CCryptoBoringSSL_XWING_parse_private_key(&self.privateKey, &cbs)
                guard rc == 1 else {
                    return false
                }

                // Matching CryptoKit, we only care that this _is_ a public key, not that it matches.
                return publicKeyBytes.count == Int(XWING_PUBLIC_KEY_BYTES)
            }
            guard parsed else {
                throw error(CryptoKitError.incorrectKeySize)
            }
        }

        init(seedRepresentation: Data, publicKeyHash: SHA3_256Digest?) throws(CryptoKitMetaError) {
            self.privateKey = .init()

            let parsed = seedRepresentation.withUnsafeBytes { privateKeyBytes in
                guard privateKeyBytes.count == Int(XWING_PRIVATE_KEY_BYTES) else {
                    return false
                }

                var cbs = CBS()
                CCryptoBoringSSL_CBS_init(&cbs, privateKeyBytes.baseAddress, privateKeyBytes.count)

                let rc = CCryptoBoringSSL_XWING_parse_private_key(&self.privateKey, &cbs)
                guard rc == 1 else {
                    return false
                }
                return true
            }
            guard parsed else {
                throw error(CryptoKitError.incorrectKeySize)
            }

            if let publicKeyHash, publicKeyHash != self.publicKeyDigest {
                throw error(KEM.Errors.publicKeyMismatchDuringInitialization)
            }
        }

        var seedRepresentation: Data {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PRIVATE_KEY_BYTES), alignment: 1) {
                var cbb = CBB()
                CCryptoBoringSSL_CBB_init_fixed(&cbb, $0.baseAddress, $0.count)
                let rc = CCryptoBoringSSL_XWING_marshal_private_key(&cbb, &self.privateKey)
                precondition(rc == 1)
                return Data($0.prefix(CCryptoBoringSSL_CBB_len(&cbb)))
            }
        }

        var integrityCheckedRepresentation: Data {
            var representation = self.seedRepresentation
            self.publicKeyDigest.withUnsafeBytes {
                representation.append(contentsOf: $0)
            }
            return representation
        }

        var dataRepresentation: Data {
            self.seedRepresentation + self.publicKey
        }

        var publicKey: Data {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_public_from_private($0.baseAddress, &self.privateKey)
                precondition(rc == 1)
                return Data($0)
            }
        }

        private var publicKeyDigest: SHA3_256Digest {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_public_from_private($0.baseAddress, &self.privateKey)
                precondition(rc == 1)
                return SHA3_256.hash(bufferPointer: UnsafeRawBufferPointer($0))
            }
        }

        static func generate() throws(CryptoKitMetaError) -> Self {
            try Self()
        }

        func decapsulate(_ encapsulated: Data) throws(CryptoKitMetaError) -> SymmetricKey {
            guard encapsulated.count == Int(XWING_CIPHERTEXT_BYTES) else {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            var sharedSecretData = Data(repeating: 0, count: Int(XWING_SHARED_SECRET_BYTES))
            let rc = sharedSecretData.withUnsafeMutableBytes { sharedSecretBytes in
                encapsulated.withUnsafeBytes { encapsulatedSecretBytes in
                    let rc = CCryptoBoringSSL_XWING_decap(
                        sharedSecretBytes.baseAddress,
                        encapsulatedSecretBytes.baseAddress,
                        &self.privateKey
                    )
                    return rc
                }
            }
            guard rc == 1 else {
                throw error(CryptoKitError.internalBoringSSLError())
            }
            return SymmetricKey(data: sharedSecretData)
        }
    }
}

#endif  // canImport(CryptoKit)
