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

#if SWIFT_CRYPTO_PURE_SWIFT
typealias MLKEM768PublicKeyImpl = SSLCryptoMLKEMPublicKeyImpl<MLKEM768>
typealias MLKEM768PrivateKeyImpl = SSLCryptoMLKEMPrivateKeyImpl<MLKEM768>
typealias MLKEM1024PublicKeyImpl = SSLCryptoMLKEMPublicKeyImpl<MLKEM1024>
typealias MLKEM1024PrivateKeyImpl = SSLCryptoMLKEMPrivateKeyImpl<MLKEM1024>
#else
typealias MLKEM768PublicKeyImpl = OpenSSLMLKEMPublicKeyImpl<MLKEM768>
typealias MLKEM768PrivateKeyImpl = OpenSSLMLKEMPrivateKeyImpl<MLKEM768>
typealias MLKEM1024PublicKeyImpl = OpenSSLMLKEMPublicKeyImpl<MLKEM1024>
typealias MLKEM1024PrivateKeyImpl = OpenSSLMLKEMPrivateKeyImpl<MLKEM1024>
#endif


/// The Module-Lattice key encapsulation mechanism (KEM).
@nonexhaustive
public enum MLKEM768: Sendable {}

extension MLKEM768 {
    /// A public key you use to encapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PublicKey: KEMPublicKey, Sendable {
        var impl: MLKEM768PublicKeyImpl

        /// Initializes a public key from a raw representation.
        /// - Parameter rawRepresentation: Data that represents the public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws(CryptoKitMetaError) {
            self.impl = try MLKEM768PublicKeyImpl(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Generates and encapsulates a shared secret.
        ///
        /// - Returns: an encapsulated shared secret, that you decapsulate by calling ``MLKEM768/PrivateKey/decapsulate(_:)`` on the corresponding private key.
        public func encapsulate() throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
            return try self.impl.encapsulate()
        }

        func encapsulateWithSeed(encapSeed: Data) throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
            return try self.impl.encapsulateWithSeed(encapSeed)
        }
    }

    /// A private key you use to decapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PrivateKey: KEMPrivateKey {
        internal let impl: MLKEM768PrivateKeyImpl

        internal init(_ impl: MLKEM768PrivateKeyImpl) {
            self.impl = impl
        }

        /// Generates a new, random private key.
        public static func generate() throws(CryptoKitMetaError) -> MLKEM768.PrivateKey {
            let impl = try MLKEM768PrivateKeyImpl.generatePrivateKey()
            return PrivateKey(impl)
        }

        static func generateWithSeed(_ seed: Data) throws(CryptoKitMetaError) -> MLKEM768.PrivateKey {
            let impl = try MLKEM768PrivateKeyImpl.generateWithSeed(seed)
            return PrivateKey(impl)
        }

        /// Initializes a random private key.
        public init() throws(CryptoKitMetaError) {
            self = try PrivateKey.generate()
        }

        /// Initializes a private key from a seed representation and optional public key.
        ///
        /// - Parameters:
        ///   - seedRepresentation: The seed representation `d||z`, as specified in the `ML-KEM.KeyGen_internal(d,z)` algorithm (Algorithm 16) of FIPS 203.
        ///   - publicKey: An optional public key. Pass this to check that the initialized private key is consistent with the public key. The initializer throws if the public key doesn't match the expected value.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLKEM768.PublicKey?) throws(CryptoKitMetaError) {
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLKEM768PrivateKeyImpl(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }

        /// The private key's seed representation.
        ///
        /// The seed is `d||z`, as specified in the algorithm `ML-KEM.KeyGen_internal(d,z)` (Algorithm 16) of FIPS 203.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM768/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public func decapsulate<D: DataProtocol>(_ encapsulated: D) throws(CryptoKitMetaError) -> SymmetricKey {
            return try impl.decapsulate(encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM768.PublicKey {
            get {
                self.impl.publicKey
            }
        }

        /// Initializes a private key from an integrity-checked representation.
        ///
        /// - Parameter integrityCheckedRepresentation: A representation of the private key that includes the seed value, and a hash of the corresponding public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws(CryptoKitMetaError) {
            guard integrityCheckedRepresentation.count == MLKEM768PrivateKeyImpl.seedSize + 32 else {
                throw error(KEM.Errors.invalidSeed)
            }
            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<MLKEM768PrivateKeyImpl.seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: MLKEM768PrivateKeyImpl.seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(copying: publicKeyHashData.bytes)

            self.impl = try MLKEM768PrivateKeyImpl(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// An integrity-checked representation of the private key.
        ///
        /// This representation includes the seed value, and a hash of the corresponding public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
            }
        }
    }

    /// A one-time-use private key to decapsulate a shared secret with the Module-Lattice key encapsulation mechanism.
    ///
    /// The associated decapsulation function can be multiple times faster than the one implemented for PrivateKey,
    /// but this private key can only be used to decapsulate a shared secret once.
    public struct OneTimePrivateKey: KEMOneTimePrivateKey, ~Copyable {
        internal let impl: MLKEM768PrivateKeyImpl

        internal init(_ impl: MLKEM768PrivateKeyImpl) {
            self.impl = impl
        }

        /// Generates a new, random one-time-use private key.
        public static func generate() throws(CryptoKitMetaError) -> MLKEM768.OneTimePrivateKey {
            let impl = try MLKEM768PrivateKeyImpl.generatePrivateKey()
            return OneTimePrivateKey(impl)
        }

        /// Initializes a random one-time-use private key.
        public init() throws(CryptoKitMetaError) {
            self = try OneTimePrivateKey.generate()
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM768/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public consuming func decapsulate<D: DataProtocol>(_ encapsulated: D) throws(CryptoKitMetaError) -> SymmetricKey {
            return try impl.decapsulate(encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM768.PublicKey {
            get {
                self.impl.publicKey
            }
        }
    }
}


/// The Module-Lattice key encapsulation mechanism (KEM).
@nonexhaustive
public enum MLKEM1024: Sendable {}

extension MLKEM1024 {
    /// A public key you use to encapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PublicKey: KEMPublicKey, Sendable {
        var impl: MLKEM1024PublicKeyImpl

        /// Initializes a public key from a raw representation.
        /// - Parameter rawRepresentation: Data that represents the public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws(CryptoKitMetaError) {
            self.impl = try MLKEM1024PublicKeyImpl(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Generates and encapsulates a shared secret.
        ///
        /// - Returns: an encapsulated shared secret, that you decapsulate by calling ``MLKEM1024/PrivateKey/decapsulate(_:)`` on the corresponding private key.
        public func encapsulate() throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
            return try self.impl.encapsulate()
        }

        func encapsulateWithSeed(encapSeed: Data) throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
            return try self.impl.encapsulateWithSeed(encapSeed)
        }
    }

    /// A private key you use to decapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PrivateKey: KEMPrivateKey {
        internal let impl: MLKEM1024PrivateKeyImpl

        internal init(_ impl: MLKEM1024PrivateKeyImpl) {
            self.impl = impl
        }

        /// Generates a new, random private key.
        public static func generate() throws(CryptoKitMetaError) -> MLKEM1024.PrivateKey {
            let impl = try MLKEM1024PrivateKeyImpl.generatePrivateKey()
            return PrivateKey(impl)
        }

        static func generateWithSeed(_ seed: Data) throws(CryptoKitMetaError) -> MLKEM1024.PrivateKey {
            let impl = try MLKEM1024PrivateKeyImpl.generateWithSeed(seed)
            return PrivateKey(impl)
        }

        /// Initializes a random private key.
        public init() throws(CryptoKitMetaError) {
            self = try PrivateKey.generate()
        }

        /// Initializes a private key from a seed representation and optional public key.
        ///
        /// - Parameters:
        ///   - seedRepresentation: The seed representation `d||z`, as specified in the `ML-KEM.KeyGen_internal(d,z)` algorithm (Algorithm 16) of FIPS 203.
        ///   - publicKey: An optional public key. Pass this to check that the initialized private key is consistent with the public key. The initializer throws if the public key doesn't match the expected value.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLKEM1024.PublicKey?) throws(CryptoKitMetaError) {
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLKEM1024PrivateKeyImpl(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }

        /// The private key's seed representation.
        ///
        /// The seed is `d||z`, as specified in the algorithm `ML-KEM.KeyGen_internal(d,z)` (Algorithm 16) of FIPS 203.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM1024/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public func decapsulate<D: DataProtocol>(_ encapsulated: D) throws(CryptoKitMetaError) -> SymmetricKey {
            return try impl.decapsulate(encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM1024.PublicKey {
            get {
                self.impl.publicKey
            }
        }

        /// Initializes a private key from an integrity-checked representation.
        ///
        /// - Parameter integrityCheckedRepresentation: A representation of the private key that includes the seed value, and a hash of the corresponding public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws(CryptoKitMetaError) {
            guard integrityCheckedRepresentation.count == MLKEM1024PrivateKeyImpl.seedSize + 32 else {
                throw error(KEM.Errors.invalidSeed)
            }
            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<MLKEM1024PrivateKeyImpl.seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: MLKEM1024PrivateKeyImpl.seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(copying: publicKeyHashData.bytes)

            self.impl = try MLKEM1024PrivateKeyImpl(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// An integrity-checked representation of the private key.
        ///
        /// This representation includes the seed value, and a hash of the corresponding public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
            }
        }
    }

    /// A one-time-use private key to decapsulate a shared secret with the Module-Lattice key encapsulation mechanism.
    ///
    /// The associated decapsulation function can be multiple times faster than the one implemented for PrivateKey,
    /// but this private key can only be used to decapsulate a shared secret once.
    public struct OneTimePrivateKey: KEMOneTimePrivateKey, ~Copyable {
        internal let impl: MLKEM1024PrivateKeyImpl

        internal init(_ impl: MLKEM1024PrivateKeyImpl) {
            self.impl = impl
        }

        /// Generates a new, random one-time-use private key.
        public static func generate() throws(CryptoKitMetaError) -> MLKEM1024.OneTimePrivateKey {
            let impl = try MLKEM1024PrivateKeyImpl.generatePrivateKey()
            return OneTimePrivateKey(impl)
        }

        /// Initializes a random one-time-use private key.
        public init() throws(CryptoKitMetaError) {
            self = try OneTimePrivateKey.generate()
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM1024/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public consuming func decapsulate<D: DataProtocol>(_ encapsulated: D) throws(CryptoKitMetaError) -> SymmetricKey {
            return try impl.decapsulate(encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM1024.PublicKey {
            get {
                self.impl.publicKey
            }
        }
    }
}


#endif // canImport(CryptoKit)
