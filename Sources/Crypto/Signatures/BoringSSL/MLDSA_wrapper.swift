//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
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
import CryptoKit
#else
internal import CCryptoBoringSSL

protocol BoringSSLBackedMLDSAPrivateKey: Sendable {
    associatedtype AssociatedPublicKey: BoringSSLBackedMLDSAPublicKey

    init() throws(CryptoKitError)

    init<D: DataProtocol>(seedRepresentation: D) throws(CryptoKitError)

    func signature<D: DataProtocol>(for data: D) throws(CryptoKitError) -> Data

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws(CryptoKitError) -> Data

    var publicKey: AssociatedPublicKey { get }

    var seedRepresentation: Data { get }
}

protocol BoringSSLBackedMLDSAPublicKey: Sendable {
    init<D: DataProtocol>(rawRepresentation: D) throws(CryptoKitError)

    func isValidSignature<S: DataProtocol, D: DataProtocol>(_: S, for data: D) -> Bool

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_: S, for data: D, context: C) -> Bool

    var rawRepresentation: Data { get }
}

protocol BoringSSLBackedMLDSAParameters {
    associatedtype BackingPrivateKey: BoringSSLBackedMLDSAPrivateKey
    where BackingPrivateKey.AssociatedPublicKey == BackingPublicKey
    associatedtype BackingPublicKey: BoringSSLBackedMLDSAPublicKey
}

extension MLDSA65: BoringSSLBackedMLDSAParameters {
    typealias BackingPrivateKey = MLDSA65.InternalPrivateKey
    typealias BackingPublicKey = MLDSA65.InternalPublicKey
}

extension MLDSA87: BoringSSLBackedMLDSAParameters {
    typealias BackingPrivateKey = MLDSA87.InternalPrivateKey
    typealias BackingPublicKey = MLDSA87.InternalPublicKey
}

extension MLDSA65.InternalPrivateKey: BoringSSLBackedMLDSAPrivateKey {}

extension MLDSA65.InternalPublicKey: BoringSSLBackedMLDSAPublicKey {}

extension MLDSA87.InternalPrivateKey: BoringSSLBackedMLDSAPrivateKey {}

extension MLDSA87.InternalPublicKey: BoringSSLBackedMLDSAPublicKey {}

struct OpenSSLMLDSAPrivateKeyImpl<Parameters: BoringSSLBackedMLDSAParameters> {
    private var backing: Parameters.BackingPrivateKey
    private let publicKeyHash: SHA3_256Digest

    init() throws(CryptoKitMetaError) {
        self.backing = try withCryptoKitError { () throws(CryptoKitError) in
            try .init()
        }
        self.publicKeyHash = SHA3_256.hash(data: self.backing.publicKey.rawRepresentation)
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyRawRepresentation: Data?) throws(CryptoKitMetaError) {
        let publicKeyHash = publicKeyRawRepresentation.map {
            SHA3_256.hash(data: $0)
        }
        self = try Self(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws(CryptoKitMetaError) {
        self.backing = try withCryptoKitError { () throws(CryptoKitError) in
            try .init(seedRepresentation: seedRepresentation)
        }
        let generatedHash = SHA3_256.hash(data: self.backing.publicKey.rawRepresentation)

        if let publicKeyHash, generatedHash != publicKeyHash {
            throw error(CryptoKitError.unwrapFailure)
        }

        self.publicKeyHash = generatedHash
    }

    func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Data {
        try withCryptoKitError { () throws(CryptoKitError) in
            try self.backing.signature(for: data)
        }
    }

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws(CryptoKitMetaError) -> Data {
        try withCryptoKitError { () throws(CryptoKitError) in
            try self.backing.signature(for: data, context: context)
        }
    }

    var publicKey: OpenSSLMLDSAPublicKeyImpl<Parameters> {
        .init(backing: self.backing.publicKey)
    }

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    var integrityCheckedRepresentation: Data {
        var representation = self.seedRepresentation
        representation.reserveCapacity(SHA3_256Digest.byteCount)
        self.publicKeyHash.withUnsafeBytes {
            representation.append(contentsOf: $0)
        }
        return representation
    }

    static var seedSize: Int {
        MLDSA.seedByteCount
    }
}

struct OpenSSLMLDSAPublicKeyImpl<Parameters: BoringSSLBackedMLDSAParameters> {
    private var backing: Parameters.BackingPublicKey

    fileprivate init(backing: Parameters.BackingPublicKey) {
        self.backing = backing
    }

    init<D: DataProtocol>(rawRepresentation: D) throws(CryptoKitMetaError) {
        self.backing = try withCryptoKitError { () throws(CryptoKitError) in
            try .init(rawRepresentation: rawRepresentation)
        }
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol>(
        _ signature: S,
        for data: D
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data)
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S,
        for data: D,
        context: C
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data, context: context)
    }

    var rawRepresentation: Data {
        self.backing.rawRepresentation
    }
}

#endif  // canImport(CryptoKit)
