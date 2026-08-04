//===----------------------------------------------------------------------===//
//
// Pure Swift ML-DSA adapters for the CryptoKit-compatible facade.
//
// The facade owns Data at its API boundary. Secret key material is retained by
// an immutable class box so the noncopyable SSLCrypto private key never escapes
// its owner and is wiped by SSLCrypto when the box is released.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCore
import SSLCrypto

protocol SSLCryptoMLDSAParameters {
    associatedtype BackendPrivateKey: ~Copyable & Sendable
    associatedtype BackendPublicKey: Sendable

    static var seedByteCount: Int { get }
    static var publicKeyByteCount: Int { get }
    static var signatureByteCount: Int { get }

    static func makePrivate(seed: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPrivateKey
    static func publicKey(
        of privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> BackendPublicKey
    static func makePublic(bytes: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPublicKey
    static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data
    static func sign(
        message: Span<UInt8>,
        context: Span<UInt8>,
        using privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> ContiguousArray<UInt8>
    static func verify(
        signature: Span<UInt8>,
        message: Span<UInt8>,
        context: Span<UInt8>,
        using publicKey: borrowing BackendPublicKey
    ) throws(SSLCrypto.MLDSAError) -> Bool
}

private func copySpan(_ span: Span<UInt8>) -> Data {
    var data = Data(repeating: 0, count: span.count)
    var index = 0
    while index < span.count {
        data[index] = span[index]
        index += 1
    }
    return data
}

extension MLDSA65: SSLCryptoMLDSAParameters {
    typealias BackendPrivateKey = SSLCrypto.MLDSA65PrivateKey
    typealias BackendPublicKey = SSLCrypto.MLDSA65PublicKey

    static let seedByteCount = SSLCrypto.MLDSA65.seedByteCount
    static let publicKeyByteCount = SSLCrypto.MLDSA65.publicKeyByteCount
    static let signatureByteCount = SSLCrypto.MLDSA65.signatureByteCount

    static func makePrivate(seed: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPrivateKey {
        try SSLCrypto.MLDSA65PrivateKey(seed: seed)
    }

    static func publicKey(
        of privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> BackendPublicKey {
        try privateKey.publicKey()
    }

    static func makePublic(bytes: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPublicKey {
        try SSLCrypto.MLDSA65PublicKey(bytes: bytes)
    }

    static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data {
        key.withBorrowedBytes(copySpan)
    }

    static func sign(
        message: Span<UInt8>,
        context: Span<UInt8>,
        using privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> ContiguousArray<UInt8> {
        try SSLCrypto.MLDSA65.sign(message: message, context: context, using: privateKey)
    }

    static func verify(
        signature: Span<UInt8>,
        message: Span<UInt8>,
        context: Span<UInt8>,
        using publicKey: borrowing BackendPublicKey
    ) throws(SSLCrypto.MLDSAError) -> Bool {
        try SSLCrypto.MLDSA65.verify(
            signature: signature,
            message: message,
            context: context,
            using: publicKey
        )
    }
}

extension MLDSA87: SSLCryptoMLDSAParameters {
    typealias BackendPrivateKey = SSLCrypto.MLDSA87PrivateKey
    typealias BackendPublicKey = SSLCrypto.MLDSA87PublicKey

    static let seedByteCount = SSLCrypto.MLDSA87.seedByteCount
    static let publicKeyByteCount = SSLCrypto.MLDSA87.publicKeyByteCount
    static let signatureByteCount = SSLCrypto.MLDSA87.signatureByteCount

    static func makePrivate(seed: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPrivateKey {
        try SSLCrypto.MLDSA87PrivateKey(seed: seed)
    }

    static func publicKey(
        of privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> BackendPublicKey {
        try privateKey.publicKey()
    }

    static func makePublic(bytes: Span<UInt8>) throws(SSLCrypto.MLDSAError) -> BackendPublicKey {
        try SSLCrypto.MLDSA87PublicKey(bytes: bytes)
    }

    static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data {
        key.withBorrowedBytes(copySpan)
    }

    static func sign(
        message: Span<UInt8>,
        context: Span<UInt8>,
        using privateKey: borrowing BackendPrivateKey
    ) throws(SSLCrypto.MLDSAError) -> ContiguousArray<UInt8> {
        try SSLCrypto.MLDSA87.sign(message: message, context: context, using: privateKey)
    }

    static func verify(
        signature: Span<UInt8>,
        message: Span<UInt8>,
        context: Span<UInt8>,
        using publicKey: borrowing BackendPublicKey
    ) throws(SSLCrypto.MLDSAError) -> Bool {
        try SSLCrypto.MLDSA87.verify(
            signature: signature,
            message: message,
            context: context,
            using: publicKey
        )
    }
}

private func mapMLDSAError(_ error: SSLCrypto.MLDSAError) -> CryptoKitError {
    switch error {
    case .invalidSeedLength, .invalidPublicKeyLength, .invalidPrivateKeyLength,
         .invalidSignatureLength, .invalidSignatureOutputLength:
        return .incorrectParameterSize
    case .invalidPrivateKeyEncoding, .contextTooLong, .inputTooLong, .entropy, .secretMemory:
        return .invalidParameter
    }
}

private final class SSLCryptoMLDSAKeyBox<Parameters: SSLCryptoMLDSAParameters>: Sendable {
    let privateKey: Parameters.BackendPrivateKey
    let publicKey: Parameters.BackendPublicKey
    let seed: Data
    let publicKeyBytes: Data
    let publicKeyHash: SHA3_256Digest

    init(
        seed: Data,
        privateKey: consuming Parameters.BackendPrivateKey,
        publicKey: consuming Parameters.BackendPublicKey
    ) {
        self.privateKey = consume privateKey
        self.publicKey = consume publicKey
        self.seed = seed
        self.publicKeyBytes = Parameters.publicKeyBytes(self.publicKey)
        self.publicKeyHash = SHA3_256.hash(data: self.publicKeyBytes)
    }
}

struct SSLCryptoMLDSAPublicKeyImpl<Parameters: SSLCryptoMLDSAParameters>: Sendable {
    private let key: Parameters.BackendPublicKey

    init<Bytes: DataProtocol>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
        var data = Data()
        data.reserveCapacity(rawRepresentation.count)
        for region in rawRepresentation.regions {
            region.withUnsafeBytes { data.append(contentsOf: $0) }
        }
        do {
            self.key = try data.withUnsafeBytes { rawBytes in
                try Parameters.makePublic(
                    bytes: Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                )
            }
        } catch let error as SSLCrypto.MLDSAError {
            throw mapMLDSAError(error)
        }
    }

    init(key: consuming Parameters.BackendPublicKey) {
        self.key = consume key
    }

    var rawRepresentation: Data {
        Parameters.publicKeyBytes(key)
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        isValidSignature(signature, for: data, context: Data())
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S,
        for data: D,
        context: C
    ) -> Bool {
        let signatureData = Data(signature)
        let messageData = Data(data)
        let contextData = Data(context)
        do {
            return try signatureData.withUnsafeBytes { signatureBytes in
                try messageData.withUnsafeBytes { messageBytes in
                    try contextData.withUnsafeBytes { contextBytes in
                        try Parameters.verify(
                            signature: Span(_unsafeElements: signatureBytes.bindMemory(to: UInt8.self)),
                            message: Span(_unsafeElements: messageBytes.bindMemory(to: UInt8.self)),
                            context: Span(_unsafeElements: contextBytes.bindMemory(to: UInt8.self)),
                            using: key
                        )
                    }
                }
            }
        } catch {
            return false
        }
    }
}

struct SSLCryptoMLDSAPrivateKeyImpl<Parameters: SSLCryptoMLDSAParameters>: Sendable {
    private let box: SSLCryptoMLDSAKeyBox<Parameters>

    init() throws(CryptoKitMetaError) {
        var seed = Data(repeating: 0, count: Parameters.seedByteCount)
        do {
            try seed.withUnsafeMutableBytes { bytes in
                var span = MutableSpan(_unsafeElements: bytes.bindMemory(to: UInt8.self))
                try SystemEntropySource().fill(&span)
            }
            self = try Self(seedRepresentation: seed, publicKeyRawRepresentation: nil)
        } catch let error as EntropyError {
            throw mapEntropyError(error)
        }
    }

    init<Bytes: DataProtocol>(
        seedRepresentation: Bytes,
        publicKeyRawRepresentation: Data?
    ) throws(CryptoKitMetaError) {
        let seed = Data(seedRepresentation)
        guard seed.count == Parameters.seedByteCount else {
            throw CryptoKitError.incorrectKeySize
        }
        do {
            let box = try seed.withUnsafeBytes { bytes in
                let privateKey = try Parameters.makePrivate(
                    seed: Span(_unsafeElements: bytes.bindMemory(to: UInt8.self))
                )
                let publicKey = try Parameters.publicKey(of: privateKey)
                return SSLCryptoMLDSAKeyBox<Parameters>(
                    seed: seed,
                    privateKey: consume privateKey,
                    publicKey: consume publicKey
                )
            }
            if let publicKeyRawRepresentation, box.publicKeyBytes != publicKeyRawRepresentation {
                throw CryptoKitError.unwrapFailure
            }
            self.box = box
        } catch let error as SSLCrypto.MLDSAError {
            throw mapMLDSAError(error)
        }
    }

    init<Bytes: DataProtocol>(
        seedRepresentation: Bytes,
        publicKeyHash: SHA3_256Digest?
    ) throws(CryptoKitMetaError) {
        try self.init(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: nil)
        if let publicKeyHash, box.publicKeyHash != publicKeyHash {
            throw CryptoKitError.unwrapFailure
        }
    }

    var seedRepresentation: Data { box.seed }

    var publicKey: SSLCryptoMLDSAPublicKeyImpl<Parameters> {
        SSLCryptoMLDSAPublicKeyImpl(key: box.publicKey)
    }

    var integrityCheckedRepresentation: Data {
        var result = box.seed
        box.publicKeyHash.withUnsafeBytes { result.append(contentsOf: $0) }
        return result
    }

    static var seedSize: Int { Parameters.seedByteCount }

    func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Data {
        try signature(for: data, context: Data())
    }

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws(CryptoKitMetaError) -> Data {
        let message = Data(data)
        let contextData = Data(context)
        do {
            let signature = try message.withUnsafeBytes { messageBytes in
                try contextData.withUnsafeBytes { contextBytes in
                    try Parameters.sign(
                        message: Span(_unsafeElements: messageBytes.bindMemory(to: UInt8.self)),
                        context: Span(_unsafeElements: contextBytes.bindMemory(to: UInt8.self)),
                        using: box.privateKey
                    )
                }
            }
            return Data(signature)
        } catch let error as SSLCrypto.MLDSAError {
            throw mapMLDSAError(error)
        }
    }
}

private func mapEntropyError(_ error: EntropyError) -> CryptoKitError {
    .invalidParameter
}

typealias MLDSAPublicKeyImpl = SSLCryptoMLDSAPublicKeyImpl
typealias MLDSAPrivateKeyImpl = SSLCryptoMLDSAPrivateKeyImpl

#endif
