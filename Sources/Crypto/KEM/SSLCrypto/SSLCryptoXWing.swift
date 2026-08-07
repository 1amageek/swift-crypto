//===----------------------------------------------------------------------===//
//
// Pure Swift X-Wing (ML-KEM-768 + X25519) implementation.
//
// The private backend keys are move-only SSLCrypto owners held by one immutable
// box. Public API Data values are materialized only at the Crypto facade
// boundary; all primitive operations borrow spans for their full call scope.
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

private enum XWingConstants {
    static let seedByteCount = 32
    static let mlkemPublicKeyByteCount = SSLCrypto.MLKEM768.PublicKey.byteCount
    static let mlkemCiphertextByteCount = SSLCrypto.MLKEM768.Encapsulation.byteCount
    static let publicKeyByteCount = mlkemPublicKeyByteCount + 32
    static let ciphertextByteCount = mlkemCiphertextByteCount + 32
    static let sharedSecretByteCount = 32
    static let expandedSeedByteCount = 96
    static let combinerLabel: [UInt8] = [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C]
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

private func mapXWingError(_ error: CryptoInputError) -> CryptoKitError {
    switch error {
    case .invalidLength, .invalidOutputLength:
        return .incorrectParameterSize
    case .invalidPeerKey, .invalidRange, .nonCanonicalEncoding, .contextTooLong, .inputTooLong,
         .invalidSignature:
        return .invalidParameter
    }
}

private func mapKEMError(_ error: SSLCrypto.KEMError) -> CryptoKitError {
    switch error {
    case .invalidPublicKeyLength, .invalidPrivateKeyLength,
         .invalidEncapsulationLength, .invalidSharedSecretLength:
        return .incorrectParameterSize
    case .invalidPublicKeyEncoding, .invalidPrivateKeyEncoding,
         .primitiveFailure, .secretMemory, .entropy:
        return .invalidParameter
    }
}

private func materialize<D: DataProtocol>(_ value: D) -> Data {
    var data = Data()
    data.reserveCapacity(value.count)
    for region in value.regions {
        region.withUnsafeBytes { data.append(contentsOf: $0) }
    }
  return data
}

// Unsafe boundary invariants:
// - storage points to one allocated, uninitialized X25519 key slot.
// - seed remains valid for this synchronous call and does not alias storage.
// - success initializes storage exactly once; failure leaves it uninitialized.
// - neither pointer nor Span escapes this function or crosses a Sendable boundary.
private func initializeX25519PrivateKey(
    seed: Span<UInt8>,
    at storage: UnsafeMutablePointer<SSLCrypto.X25519PrivateKey>
) -> CryptoInputError? {
    do {
        storage.initialize(to: try SSLCrypto.X25519PrivateKey(bytes: seed))
        return nil
    } catch {
        return error
    }
}

/// Creates a move-only X25519 key without returning it through a
/// `ContiguousBytes` borrow closure. The allocated slot owns the key until
/// `move()` transfers it, and the slot is deallocated exactly once.
private func makeX25519PrivateKey(_ seed: Data) throws(CryptoInputError) -> SSLCrypto.X25519PrivateKey {
  let storage = UnsafeMutablePointer<SSLCrypto.X25519PrivateKey>.allocate(capacity: 1)
  var initialized = false
  defer {
    if initialized {
      storage.deinitialize(count: 1)
    }
    storage.deallocate()
  }

  let initializationError = seed.withUnsafeBytes { bytes in
    initializeX25519PrivateKey(
      seed: Span(_unsafeElements: bytes.bindMemory(to: UInt8.self)),
      at: storage
    )
  }
  if let error = initializationError {
    throw error
  }
  initialized = true

  let key = storage.move()
  initialized = false
  return key
}

private func expandSeed(_ seed: Data) throws(CryptoKitMetaError) -> (Data, Data) {
    var expanded = ContiguousArray<UInt8>(repeating: 0, count: XWingConstants.expandedSeedByteCount)
    do {
        try seed.withUnsafeBytes { bytes in
            var output = expanded.mutableSpan
            try SSLCrypto.SHAKE256.hash(
                Span(_unsafeElements: bytes.bindMemory(to: UInt8.self)),
                outputByteCount: XWingConstants.expandedSeedByteCount,
                into: &output
            )
        }
    } catch let error as CryptoInputError {
        throw mapXWingError(error)
    }
    let expandedData = Data(expanded)
    return (
        expandedData.subdata(in: 0..<64),
        expandedData.subdata(in: 64..<XWingConstants.expandedSeedByteCount)
    )
}

private func combine(
    mlkemSecret: Span<UInt8>,
    x25519Secret: Span<UInt8>,
    x25519Ciphertext: Span<UInt8>,
    x25519PublicKey: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
) throws(CryptoKitMetaError) {
    guard output.count == XWingConstants.sharedSecretByteCount else {
        throw CryptoKitError.incorrectParameterSize
    }
    do {
        var context = SSLCrypto.SHA3_256.makeContext()
        try context.update(mlkemSecret)
        try context.update(x25519Secret)
        try context.update(x25519Ciphertext)
        try context.update(x25519PublicKey)
        let label = XWingConstants.combinerLabel
        try label.withUnsafeBufferPointer { labelBytes in
            try context.update(Span(_unsafeElements: labelBytes))
        }
        try context.finalize(into: &output)
    } catch let error as CryptoInputError {
        throw mapXWingError(error)
    }
}

private final class SSLCryptoXWingPrivateKeyBox: Sendable {
    let seed: Data
    let mlkemPrivateKey: SSLCrypto.MLKEM768.PrivateKey
    let x25519PrivateKey: SSLCrypto.X25519PrivateKey
    let publicKey: Data

    init(
        seed: Data,
        mlkemPrivateKey: consuming SSLCrypto.MLKEM768.PrivateKey,
        x25519PrivateKey: consuming SSLCrypto.X25519PrivateKey,
        publicKey: Data
    ) {
        self.seed = seed
        self.mlkemPrivateKey = consume mlkemPrivateKey
        self.x25519PrivateKey = consume x25519PrivateKey
        self.publicKey = publicKey
    }
}

private func makePrivateBox(seed: Data) throws(CryptoKitMetaError) -> SSLCryptoXWingPrivateKeyBox {
    let (mlkemSeed, x25519Seed) = try expandSeed(seed)
    do {
        let pair = try generateSSLCryptoMLKEMKeyPair(for: MLKEM768.self, mlkemSeed)
        let x25519Private = try makeX25519PrivateKey(x25519Seed)
        let mlkemPublic = pair.publicKey.withBorrowedBytes(copySpan)
        let x25519Public = x25519Private.publicKey()
        let x25519PublicData = x25519Public.withBorrowedBytes(copySpan)
        var publicKey = mlkemPublic
        publicKey.append(x25519PublicData)
        return SSLCryptoXWingPrivateKeyBox(
            seed: seed,
            mlkemPrivateKey: consume pair.privateKey,
            x25519PrivateKey: consume x25519Private,
            publicKey: publicKey
        )
    } catch let error as SSLCrypto.KEMError {
        throw mapKEMError(error)
    } catch let error as CryptoInputError {
        throw mapXWingError(error)
    }
}

struct SSLCryptoXWingPublicKeyImpl: Sendable {
    private let bytes: Data

    init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
        let data = rawRepresentation.withUnsafeBytes { Data($0) }
        guard data.count == XWingConstants.publicKeyByteCount else {
            throw CryptoKitError.incorrectKeySize
        }
        do {
            _ = try data.withUnsafeBytes { raw in
                try SSLCrypto.MLKEM768.PublicKey(
                    bytes: Span(_unsafeElements: raw.bindMemory(to: UInt8.self).extracting(0..<XWingConstants.mlkemPublicKeyByteCount))
                )
            }
            _ = try data.withUnsafeBytes { raw in
                try SSLCrypto.X25519PublicKey(
                    bytes: Span(_unsafeElements: raw.bindMemory(to: UInt8.self).extracting(XWingConstants.mlkemPublicKeyByteCount..<XWingConstants.publicKeyByteCount))
                )
            }
        } catch let error as SSLCrypto.KEMError {
            throw mapKEMError(error)
        } catch let error as CryptoInputError {
            throw mapXWingError(error)
        }
        self.bytes = data
    }

    init(bytes: Data) {
        self.bytes = bytes
    }

    var rawRepresentation: Data { bytes }

    func encapsulate() throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
        var ephemeralEntropy = Data(repeating: 0, count: 64)
        do {
            try ephemeralEntropy.withUnsafeMutableBytes { raw in
                var entropy = MutableSpan(_unsafeElements: raw.bindMemory(to: UInt8.self))
                try SystemEntropySource().fill(&entropy)
            }
        } catch {
            throw CryptoKitError.invalidParameter
        }

        return try encapsulate(entropy: ephemeralEntropy)
    }

    func encapsulate(entropy: Data) throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
        guard entropy.count == 64 else {
            throw CryptoKitError.incorrectParameterSize
        }

        var ciphertext = ContiguousArray<UInt8>(repeating: 0, count: XWingConstants.ciphertextByteCount)
        var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: XWingConstants.sharedSecretByteCount)
        do {
            try bytes.withUnsafeBytes { publicRaw in
                try entropy.withUnsafeBytes { entropyRaw in
                    var ciphertextSpan = ciphertext.mutableSpan
                    let publicSpan = Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                    let entropySpan = Span(_unsafeElements: entropyRaw.bindMemory(to: UInt8.self))
                    let mlkemPublic = try SSLCrypto.MLKEM768.PublicKey(
                        bytes: publicSpan.extracting(0..<XWingConstants.mlkemPublicKeyByteCount)
                    )
                    let x25519Public = try SSLCrypto.X25519PublicKey(
                        bytes: publicSpan.extracting(XWingConstants.mlkemPublicKeyByteCount..<XWingConstants.publicKeyByteCount)
                    )
                    let ephemeralPrivate = try SSLCrypto.X25519PrivateKey(
                        bytes: entropySpan.extracting(32..<64)
                    )
                    var x25519Ciphertext = ciphertextSpan._mutatingExtracting(
                        XWingConstants.mlkemCiphertextByteCount..<XWingConstants.ciphertextByteCount
                    )
                    try ephemeralPrivate.publicKey(into: &x25519Ciphertext)
                    var x25519Secret = ContiguousArray<UInt8>(repeating: 0, count: 32)
                    var x25519SecretSpan = x25519Secret.mutableSpan
                    try SSLCrypto.X25519.sharedSecret(
                        privateKey: ephemeralPrivate,
                        peerPublicKey: x25519Public,
                        into: &x25519SecretSpan
                    )
                    var mlkemSecret = ContiguousArray<UInt8>(repeating: 0, count: 32)
                    var mlkemSecretSpan = mlkemSecret.mutableSpan
                    var mlkemCiphertext = ciphertextSpan._mutatingExtracting(0..<XWingConstants.mlkemCiphertextByteCount)
                    try SSLCrypto.MLKEM768.encapsulate(
                        to: mlkemPublic,
                        message: entropySpan.extracting(0..<32),
                        into: &mlkemCiphertext,
                        sharedSecret: &mlkemSecretSpan
                    )
                    var combined = sharedSecret.mutableSpan
                    try combine(
                        mlkemSecret: mlkemSecret.span,
                        x25519Secret: x25519Secret.span,
                        x25519Ciphertext: ciphertext.span.extracting(
                            XWingConstants.mlkemCiphertextByteCount..<XWingConstants.ciphertextByteCount
                        ),
                        x25519PublicKey: publicSpan.extracting(XWingConstants.mlkemPublicKeyByteCount..<XWingConstants.publicKeyByteCount),
                        into: &combined
                    )
                }
            }
        } catch let error as SSLCrypto.KEMError {
            throw mapKEMError(error)
        } catch let error as CryptoInputError {
            throw mapXWingError(error)
        }
        return KEM.EncapsulationResult(
            sharedSecret: SymmetricKey(data: Data(sharedSecret)),
            encapsulated: Data(ciphertext)
        )
    }
}

struct SSLCryptoXWingPrivateKeyImpl: Sendable {
    private let box: SSLCryptoXWingPrivateKeyBox

    init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws(CryptoKitMetaError) {
        let seed = materialize(seedRepresentation)
        guard seed.count == XWingConstants.seedByteCount else {
            throw CryptoKitError.incorrectKeySize
        }
        let box = try makePrivateBox(seed: seed)
        if let publicKeyHash, SHA3_256.hash(data: box.publicKey) != publicKeyHash {
            throw KEM.Errors.publicKeyMismatchDuringInitialization
        }
        self.box = box
    }

    init<D: ContiguousBytes>(bytes: D) throws(CryptoKitMetaError) {
        let representation = bytes.withUnsafeBytes { Data($0) }
        guard representation.count == XWingConstants.seedByteCount + XWingConstants.publicKeyByteCount else {
            throw CryptoKitError.incorrectKeySize
        }
        let seed = representation.prefix(XWingConstants.seedByteCount)
        let suppliedPublicKey = representation.suffix(XWingConstants.publicKeyByteCount)
        let box = try makePrivateBox(seed: Data(seed))
        guard box.publicKey == suppliedPublicKey else {
            throw KEM.Errors.publicKeyMismatchDuringInitialization
        }
        self.box = box
    }

    static func generate() throws(CryptoKitMetaError) -> Self {
        var seed = Data(repeating: 0, count: XWingConstants.seedByteCount)
        do {
            try seed.withUnsafeMutableBytes { raw in
                var output = MutableSpan(_unsafeElements: raw.bindMemory(to: UInt8.self))
                try SystemEntropySource().fill(&output)
            }
        } catch {
            throw CryptoKitError.invalidParameter
        }
        return try Self(seedRepresentation: seed, publicKeyHash: nil)
    }

    var seedRepresentation: Data { box.seed }

    var integrityCheckedRepresentation: Data {
        var representation = box.seed
        SHA3_256.hash(data: box.publicKey).withUnsafeBytes {
            representation.append(contentsOf: $0)
        }
        return representation
    }

    var dataRepresentation: Data {
        box.seed + box.publicKey
    }

    var publicKey: SSLCryptoXWingPublicKeyImpl {
        SSLCryptoXWingPublicKeyImpl(bytes: box.publicKey)
    }

    func decapsulate(_ encapsulated: Data) throws(CryptoKitMetaError) -> SymmetricKey {
        guard encapsulated.count == XWingConstants.ciphertextByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }
        var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: XWingConstants.sharedSecretByteCount)
        do {
            try encapsulated.withUnsafeBytes { ciphertextRaw in
                var sharedSecretSpan = sharedSecret.mutableSpan
                let ciphertext = Span(_unsafeElements: ciphertextRaw.bindMemory(to: UInt8.self))
                var mlkemSecret = ContiguousArray<UInt8>(repeating: 0, count: 32)
                var mlkemSecretSpan = mlkemSecret.mutableSpan
                try SSLCrypto.MLKEM768.decapsulate(
                    ciphertext.extracting(0..<XWingConstants.mlkemCiphertextByteCount),
                    using: box.mlkemPrivateKey,
                    into: &mlkemSecretSpan
                )
                let x25519Ciphertext = ciphertext.extracting(XWingConstants.mlkemCiphertextByteCount..<XWingConstants.ciphertextByteCount)
                var x25519Secret = ContiguousArray<UInt8>(repeating: 0, count: 32)
                var x25519SecretSpan = x25519Secret.mutableSpan
                try SSLCrypto.X25519.sharedSecret(
                    privateKey: box.x25519PrivateKey,
                    peerPublicKeyBytes: x25519Ciphertext,
                    into: &x25519SecretSpan
                )
                var x25519Public = ContiguousArray<UInt8>(repeating: 0, count: 32)
                var x25519PublicSpan = x25519Public.mutableSpan
                try box.x25519PrivateKey.publicKey(into: &x25519PublicSpan)
                try combine(
                    mlkemSecret: mlkemSecret.span,
                    x25519Secret: x25519Secret.span,
                    x25519Ciphertext: x25519Ciphertext,
                    x25519PublicKey: x25519Public.span,
                    into: &sharedSecretSpan
                )
            }
        } catch let error as SSLCrypto.KEMError {
            throw mapKEMError(error)
        } catch let error as CryptoInputError {
            throw mapXWingError(error)
        }
        return SymmetricKey(data: Data(sharedSecret))
    }
}

#endif
