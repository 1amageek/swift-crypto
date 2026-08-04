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


/// A type that ``HPKE`` uses to encode the public key.
public protocol HPKEPublicKeySerialization: Sendable {
	/// Creates a public key from an encoded representation.
	///
	/// - Parameters:
	///  - serialization: The serialized key data.
	///  - kem: The key encapsulation mechanism that the sender used to encapsulate the key.
    init<D: ContiguousBytes>(_ serialization: D, kem: HPKE.KEM) throws(CryptoKitMetaError)
	/// Creates an encoded representation of the public key.
	///
	/// - Parameters:
	///  - kem: The key encapsulation mechanism for encapsulating the key.
    ///  
	/// - Returns: The encoded key data.
    func hpkeRepresentation(kem: HPKE.KEM) throws(CryptoKitMetaError) -> Data
}

/// A type that represents the public key in a Diffie-Hellman key exchange.
public protocol HPKEDiffieHellmanPublicKey: HPKEPublicKeySerialization, Sendable where EphemeralPrivateKey.PublicKey == Self {
	/// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEDiffieHellmanPrivateKeyGeneration
}

/// A type that represents the public key in HPKE
public protocol HPKEKEMPublicKey: KEMPublicKey, HPKEPublicKeySerialization where EphemeralPrivateKey.PublicKey == Self {
    /// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEKEMPrivateKeyGeneration
}

/// A type that represents the private key in a Diffie-Hellman key exchange.
public protocol HPKEDiffieHellmanPrivateKey: Sendable, DiffieHellmanKeyAgreement where PublicKey: HPKEDiffieHellmanPublicKey {}

/// A type that represents the private key in HPKE.
public protocol HPKEKEMPrivateKey: Sendable, KEMPrivateKey where PublicKey: HPKEKEMPublicKey {}

/// A type that represents the generation of private keys in a Diffie-Hellman key exchange.
public protocol HPKEDiffieHellmanPrivateKeyGeneration: HPKEDiffieHellmanPrivateKey, Sendable {
	/// Creates a private key generator.
    init()
}

/// A type that represents the generation of private keys in HPKE
public protocol HPKEKEMPrivateKeyGeneration: HPKEKEMPrivateKey, Sendable {
    /// Creates a private key generator.
    init() throws(CryptoKitMetaError)
}

extension HPKE {
	/// A container for Diffie-Hellman key encapsulation mechanisms (KEMs).
    @nonexhaustive
    public enum DHKEM: Sendable {
        struct PublicKey<DHPK: HPKEDiffieHellmanPublicKey>: KEMPublicKey
            where DHPK == DHPK.EphemeralPrivateKey.PublicKey {
            let kem: HPKE.KEM
            let key: DHPK
            typealias EncapsulationResult = Crypto.KEM.EncapsulationResult

            init(_ publicKey: DHPK, kem: HPKE.KEM) throws(CryptoKitMetaError) {
                _ = try publicKey.hpkeRepresentation(kem: kem)
                self.init(validatedKey: publicKey, kem: kem)
            }

            init(validatedKey publicKey: DHPK, kem: HPKE.KEM) {
                self.key = publicKey
                self.kem = kem
            }

            func encapsulate() throws(CryptoKitMetaError) -> EncapsulationResult {
                let ephemeralKeys = DHPK.EphemeralPrivateKey()
                let sharedSecret = try ephemeralKeys.sharedSecretFromKeyAgreement(
                    with: key
                )

                let encapsulatedKey = try ephemeralKeys.publicKey.hpkeRepresentation(
                    kem: kem
                )
                let recipientPublicKey = try key.hpkeRepresentation(kem: kem)
                return EncapsulationResult(
                    sharedSecret: HPKE.KeyExchangeDerivation.extractAndExpand(
                        sharedSecret: sharedSecret,
                        encapsulatedKey: encapsulatedKey,
                        recipientPublicKey: recipientPublicKey,
                        kem: kem,
                        kdf: kem.kdf
                    ),
                    encapsulated: encapsulatedKey
                )
            }
        }

        struct PrivateKey<DHSK: HPKEDiffieHellmanPrivateKey> {
            typealias PublicKey = HPKE.DHKEM.PublicKey<DHSK.PublicKey>

            let kem: HPKE.KEM
            let key: DHSK

            init(_ privateKey: DHSK, kem: HPKE.KEM) throws(CryptoKitMetaError) {
                _ = try privateKey.publicKey.hpkeRepresentation(kem: kem)
                self.key = privateKey
                self.kem = kem
            }

            func decapsulate(
                _ encapsulated: Data
            ) throws(CryptoKitMetaError) -> SymmetricKey {
                let ephemeralPublicKey = try DHSK.PublicKey(encapsulated, kem: kem)
                let sharedSecret = try key.sharedSecretFromKeyAgreement(
                    with: ephemeralPublicKey
                )

                return HPKE.KeyExchangeDerivation.extractAndExpand(
                    sharedSecret: sharedSecret,
                    encapsulatedKey: encapsulated,
                    recipientPublicKey: try key.publicKey.hpkeRepresentation(kem: kem),
                    kem: kem,
                    kdf: kem.kdf
                )
            }

            func decapsulate(
                _ encapsulated: Data,
                authenticating senderPublicKey: DHSK.PublicKey
            ) throws(CryptoKitMetaError) -> SymmetricKey {
                let ephemeralPublicKey = try DHSK.PublicKey(encapsulated, kem: kem)

                let ephemeralSharedSecret = try key.sharedSecretFromKeyAgreement(
                    with: ephemeralPublicKey
                )
                let authenticationSharedSecret = try key.sharedSecretFromKeyAgreement(
                    with: senderPublicKey
                )

                return HPKE.KeyExchangeDerivation.extractAndExpand(
                    ephemeralSharedSecret: ephemeralSharedSecret,
                    authenticationSharedSecret: authenticationSharedSecret,
                    encapsulatedKey: encapsulated,
                    recipientPublicKey: try key.publicKey.hpkeRepresentation(kem: kem),
                    senderPublicKey: try senderPublicKey.hpkeRepresentation(kem: kem),
                    kem: kem,
                    kdf: kem.kdf
                )
            }

            func authenticateAndEncapsulateTo(
                _ publicKey: PublicKey
            ) throws(CryptoKitMetaError) -> (
                sharedSecret: SymmetricKey,
                encapsulated: Data
            ) {
                let ephemeralKeys = DHSK.PublicKey.EphemeralPrivateKey()

                let ephemeralSharedSecret = try ephemeralKeys.sharedSecretFromKeyAgreement(
                    with: publicKey.key
                )
                let authenticationSharedSecret = try key.sharedSecretFromKeyAgreement(
                    with: publicKey.key
                )
                let encapsulatedKey = try ephemeralKeys.publicKey.hpkeRepresentation(
                    kem: kem
                )

                return (
                    HPKE.KeyExchangeDerivation.extractAndExpand(
                        ephemeralSharedSecret: ephemeralSharedSecret,
                        authenticationSharedSecret: authenticationSharedSecret,
                        encapsulatedKey: encapsulatedKey,
                        recipientPublicKey: try publicKey.key.hpkeRepresentation(kem: kem),
                        senderPublicKey: try key.publicKey.hpkeRepresentation(kem: kem),
                        kem: kem,
                        kdf: kem.kdf
                    ),
                    encapsulatedKey
                )
            }

            var publicKey: PublicKey {
                HPKE.DHKEM.PublicKey(validatedKey: key.publicKey, kem: kem)
            }
        }
    }
}

#endif // canImport(CryptoKit)
