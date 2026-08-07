#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCore
import SSLCrypto

private func copySSLCryptoSpan(_ span: Span<UInt8>) -> Data {
  var data = Data(repeating: 0, count: span.count)
  var index = 0
  while index < span.count {
    data[index] = span[index]
    index += 1
  }
  return data
}

protocol SSLCryptoMLKEMParameters {
  associatedtype BackendPublicKey: Sendable
  associatedtype BackendPrivateKey: ~Copyable & Sendable
  associatedtype OuterPublicKey: Sendable

  static var seedByteCount: Int { get }
  static var publicKeyByteCount: Int { get }
  static var ciphertextByteCount: Int { get }
  static var sharedSecretByteCount: Int { get }

  static func generateKeyPair(seed: Span<UInt8>) throws(SSLCrypto.KEMError)
    -> SSLCrypto.KEMKeyPair<BackendPublicKey, BackendPrivateKey>
  static func makePublicKey(bytes: Span<UInt8>) throws(SSLCrypto.KEMError) -> BackendPublicKey
  static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data
  static func makeOuterPublicKey(rawRepresentation: Data) throws(CryptoKitMetaError) -> OuterPublicKey
  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    message: Span<UInt8>,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError)
  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError)
  static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing BackendPrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError)
}

// Unsafe boundary invariants:
// - storage points to one allocated, uninitialized Pair slot owned by the caller.
// - seed remains valid for this synchronous call and does not alias storage.
// - success initializes storage exactly once; failure leaves it uninitialized.
// - neither pointer nor Span escapes this function or crosses a Sendable boundary.
private func initializeSSLCryptoMLKEMKeyPair<Parameters: SSLCryptoMLKEMParameters>(
  for _: Parameters.Type,
  seed: Span<UInt8>,
  at storage: UnsafeMutablePointer<
    SSLCrypto.KEMKeyPair<Parameters.BackendPublicKey, Parameters.BackendPrivateKey>
  >
) -> SSLCrypto.KEMError? {
  do {
    storage.initialize(to: try Parameters.generateKeyPair(seed: seed))
    return nil
  } catch {
    return error
  }
}

/// Materializes a move-only backend key pair without returning it through the
/// `ContiguousBytes` borrow closure. Embedded Swift keeps that closure's result
/// copyable, so the temporary pointer is the explicit owner for this boundary.
/// The pointer is initialized exactly once, moved exactly once, and deallocated
/// after the move; the borrowed byte pointer never escapes the closure.
func generateSSLCryptoMLKEMKeyPair<Parameters: SSLCryptoMLKEMParameters>(
  for _: Parameters.Type,
  _ seed: Data
) throws(SSLCrypto.KEMError) -> SSLCrypto.KEMKeyPair<Parameters.BackendPublicKey, Parameters.BackendPrivateKey> {
  typealias Pair = SSLCrypto.KEMKeyPair<Parameters.BackendPublicKey, Parameters.BackendPrivateKey>
  let storage = UnsafeMutablePointer<Pair>.allocate(capacity: 1)
  var initialized = false
  defer {
    if initialized {
      storage.deinitialize(count: 1)
    }
    storage.deallocate()
  }

  let generationError = seed.withUnsafeBytes { rawBytes in
    initializeSSLCryptoMLKEMKeyPair(
      for: Parameters.self,
      seed: Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)),
      at: storage
    )
  }
  if let error = generationError {
    throw error
  }
  initialized = true

  let pair = storage.move()
  initialized = false
  return pair
}

extension MLKEM768: SSLCryptoMLKEMParameters {
  typealias BackendPublicKey = SSLCrypto.MLKEM768.PublicKey
  typealias BackendPrivateKey = SSLCrypto.MLKEM768.PrivateKey
  typealias OuterPublicKey = MLKEM768.PublicKey

  static let seedByteCount = 64
  static let publicKeyByteCount = SSLCrypto.MLKEM768.PublicKey.byteCount
  static let ciphertextByteCount = SSLCrypto.MLKEM768.Encapsulation.byteCount
  static let sharedSecretByteCount = SSLCrypto.MLKEM768.SharedSecret.byteCount

  static func generateKeyPair(seed: Span<UInt8>) throws(SSLCrypto.KEMError)
    -> SSLCrypto.KEMKeyPair<BackendPublicKey, BackendPrivateKey> {
    try SSLCrypto.MLKEM768.generateKeyPair(seed: seed)
  }

  static func makePublicKey(bytes: Span<UInt8>) throws(SSLCrypto.KEMError) -> BackendPublicKey {
    try SSLCrypto.MLKEM768.PublicKey(bytes: bytes)
  }

  static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data {
    key.withBorrowedBytes(copySSLCryptoSpan)
  }

  static func makeOuterPublicKey(rawRepresentation: Data) throws(CryptoKitMetaError) -> MLKEM768.PublicKey {
    try MLKEM768.PublicKey(rawRepresentation: rawRepresentation)
  }

  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    message: Span<UInt8>,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM768.encapsulate(
      to: publicKey,
      message: message,
      into: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM768.encapsulate(
      to: publicKey,
      into: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing BackendPrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM768.decapsulate(
      encapsulation,
      using: privateKey,
      into: &sharedSecret
    )
  }
}

extension MLKEM1024: SSLCryptoMLKEMParameters {
  typealias BackendPublicKey = SSLCrypto.MLKEM1024.PublicKey
  typealias BackendPrivateKey = SSLCrypto.MLKEM1024.PrivateKey
  typealias OuterPublicKey = MLKEM1024.PublicKey

  static let seedByteCount = 64
  static let publicKeyByteCount = SSLCrypto.MLKEM1024.PublicKey.byteCount
  static let ciphertextByteCount = SSLCrypto.MLKEM1024.Encapsulation.byteCount
  static let sharedSecretByteCount = SSLCrypto.MLKEM1024.SharedSecret.byteCount

  static func generateKeyPair(seed: Span<UInt8>) throws(SSLCrypto.KEMError)
    -> SSLCrypto.KEMKeyPair<BackendPublicKey, BackendPrivateKey> {
    try SSLCrypto.MLKEM1024.generateKeyPair(seed: seed)
  }

  static func makePublicKey(bytes: Span<UInt8>) throws(SSLCrypto.KEMError) -> BackendPublicKey {
    try SSLCrypto.MLKEM1024.PublicKey(bytes: bytes)
  }

  static func publicKeyBytes(_ key: borrowing BackendPublicKey) -> Data {
    key.withBorrowedBytes(copySSLCryptoSpan)
  }

  static func makeOuterPublicKey(rawRepresentation: Data) throws(CryptoKitMetaError) -> MLKEM1024.PublicKey {
    try MLKEM1024.PublicKey(rawRepresentation: rawRepresentation)
  }

  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    message: Span<UInt8>,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM1024.encapsulate(
      to: publicKey,
      message: message,
      into: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  static func encapsulate(
    to publicKey: borrowing BackendPublicKey,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM1024.encapsulate(
      to: publicKey,
      into: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing BackendPrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(SSLCrypto.KEMError) {
    try SSLCrypto.MLKEM1024.decapsulate(
      encapsulation,
      using: privateKey,
      into: &sharedSecret
    )
  }
}

private func mapSSLCryptoKEMError(_ error: SSLCrypto.KEMError) -> CryptoKitError {
  switch error {
  case .invalidPublicKeyLength, .invalidPrivateKeyLength, .invalidEncapsulationLength,
       .invalidSharedSecretLength:
    return .incorrectParameterSize
  case .invalidPublicKeyEncoding, .invalidPrivateKeyEncoding, .primitiveFailure,
       .secretMemory, .entropy:
    return .invalidParameter
  }
}

final class SSLCryptoMLKEMKeyBox<Parameters: SSLCryptoMLKEMParameters>: Sendable {
  let publicKey: Parameters.BackendPublicKey
  let privateKey: Parameters.BackendPrivateKey
  let seed: Data

  init(
    seed: Data,
    publicKey: consuming Parameters.BackendPublicKey,
    privateKey: consuming Parameters.BackendPrivateKey
  ) {
    self.seed = seed
    self.publicKey = consume publicKey
    self.privateKey = consume privateKey
  }
}

struct SSLCryptoMLKEMPublicKeyImpl<Parameters: SSLCryptoMLKEMParameters>: Sendable {
  private let key: Parameters.BackendPublicKey

  init<Bytes: DataProtocol>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
    var bytes = Data()
    bytes.reserveCapacity(rawRepresentation.count)
    for region in rawRepresentation.regions {
      region.withUnsafeBytes { bytes.append(contentsOf: $0) }
    }
    do {
      self.key = try bytes.withUnsafeBytes { rawBytes in
        try Parameters.makePublicKey(bytes: Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
      }
    } catch let error as SSLCrypto.KEMError {
      throw mapSSLCryptoKEMError(error)
    }
  }

  init(key: consuming Parameters.BackendPublicKey) {
    self.key = consume key
  }

  var rawRepresentation: Data { Parameters.publicKeyBytes(key) }

  static var byteCount: Int { Parameters.publicKeyByteCount }

  func encapsulate() throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
    var encapsulated = ContiguousArray<UInt8>(repeating: 0, count: Parameters.ciphertextByteCount)
    var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: Parameters.sharedSecretByteCount)
    do {
      try encapsulated.withUnsafeMutableBufferPointer { encapsulatedBuffer in
        try sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
          var encapsulatedSpan = MutableSpan(_unsafeElements: encapsulatedBuffer)
          var sharedSecretSpan = MutableSpan(_unsafeElements: sharedSecretBuffer)
          try Parameters.encapsulate(
            to: key,
            into: &encapsulatedSpan,
            sharedSecret: &sharedSecretSpan
          )
        }
      }
    } catch let error as SSLCrypto.KEMError {
      throw mapSSLCryptoKEMError(error)
    }
    return KEM.EncapsulationResult(
      sharedSecret: SymmetricKey(data: Data(sharedSecret)),
      encapsulated: Data(encapsulated)
    )
  }

  func encapsulateWithSeed(_ seed: Data) throws(CryptoKitMetaError) -> KEM.EncapsulationResult {
    guard seed.count == 32 else {
      throw CryptoKitError.incorrectParameterSize
    }
    var encapsulated = ContiguousArray<UInt8>(repeating: 0, count: Parameters.ciphertextByteCount)
    var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: Parameters.sharedSecretByteCount)
    do {
      try seed.withUnsafeBytes { seedBytes in
        try encapsulated.withUnsafeMutableBufferPointer { encapsulatedBuffer in
          try sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
            var encapsulatedSpan = MutableSpan(_unsafeElements: encapsulatedBuffer)
            var sharedSecretSpan = MutableSpan(_unsafeElements: sharedSecretBuffer)
            try Parameters.encapsulate(
              to: key,
              message: Span(_unsafeElements: seedBytes.bindMemory(to: UInt8.self)),
              into: &encapsulatedSpan,
              sharedSecret: &sharedSecretSpan
            )
          }
        }
      }
    } catch let error as SSLCrypto.KEMError {
      throw mapSSLCryptoKEMError(error)
    }
    return KEM.EncapsulationResult(
      sharedSecret: SymmetricKey(data: Data(sharedSecret)),
      encapsulated: Data(encapsulated)
    )
  }
}

struct SSLCryptoMLKEMPrivateKeyImpl<Parameters: SSLCryptoMLKEMParameters>: Sendable {
  private let box: SSLCryptoMLKEMKeyBox<Parameters>

  init() throws(CryptoKitMetaError) {
    var seed = Data(repeating: 0, count: Parameters.seedByteCount)
    do {
      try seed.withUnsafeMutableBytes { rawBytes in
        var span = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
        try SystemEntropySource().fill(&span)
      }
      self = try Self(seedRepresentation: seed, publicKeyRawRepresentation: nil)
    } catch let error as EntropyError {
      throw mapEntropyError(error)
    } catch let error as CryptoKitError {
      throw error
    }
  }

  static func generatePrivateKey() throws(CryptoKitMetaError) -> Self {
    try Self()
  }

  static func generateWithSeed(_ seed: Data) throws(CryptoKitMetaError) -> Self {
    try Self(seedRepresentation: seed, publicKeyRawRepresentation: nil)
  }

  init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyRawRepresentation: Data?) throws(CryptoKitMetaError) {
    var seed = Data()
    seed.reserveCapacity(seedRepresentation.count)
    for region in seedRepresentation.regions {
      region.withUnsafeBytes { seed.append(contentsOf: $0) }
    }
    guard seed.count == Parameters.seedByteCount else {
      throw CryptoKitError.incorrectKeySize
    }
    do {
      let pair = try generateSSLCryptoMLKEMKeyPair(for: Parameters.self, seed)
      let generatedPublicData = Parameters.publicKeyBytes(pair.publicKey)
      if let publicKeyRawRepresentation {
        guard generatedPublicData == publicKeyRawRepresentation else {
          throw KEM.Errors.publicKeyMismatchDuringInitialization
        }
      }
      self.box = pair.withConsumedKeys { publicKey, privateKey in
        SSLCryptoMLKEMKeyBox(
          seed: seed,
          publicKey: consume publicKey,
          privateKey: consume privateKey
        )
      }
    } catch let error as SSLCrypto.KEMError {
      throw mapSSLCryptoKEMError(error)
    }
  }

  init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyHash: SHA3_256Digest?) throws(CryptoKitMetaError) {
    try self.init(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: nil)
    if let publicKeyHash, SHA3_256.hash(data: self.interiorPublicKey.rawRepresentation) != publicKeyHash {
      throw KEM.Errors.publicKeyMismatchDuringInitialization
    }
  }

  var seedRepresentation: Data { box.seed }

  var interiorPublicKey: SSLCryptoMLKEMPublicKeyImpl<Parameters> {
    SSLCryptoMLKEMPublicKeyImpl(key: box.publicKey)
  }

  var publicKey: Parameters.OuterPublicKey {
    // The backend key was validated before it entered the owner.
    try! Parameters.makeOuterPublicKey(rawRepresentation: interiorPublicKey.rawRepresentation)
  }

  static var seedSize: Int { Parameters.seedByteCount }

  var integrityCheckedRepresentation: Data {
    var representation = box.seed
    SHA3_256.hash(data: interiorPublicKey.rawRepresentation).withUnsafeBytes {
      representation.append(contentsOf: $0)
    }
    return representation
  }

  func decapsulate<Bytes: DataProtocol>(_ encapsulated: Bytes) throws(CryptoKitMetaError) -> SymmetricKey {
    var ciphertext = Data()
    ciphertext.reserveCapacity(encapsulated.count)
    for region in encapsulated.regions {
      region.withUnsafeBytes { ciphertext.append(contentsOf: $0) }
    }
    var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: Parameters.sharedSecretByteCount)
    do {
      try ciphertext.withUnsafeBytes { ciphertextBytes in
        try sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
          var sharedSecretSpan = MutableSpan(_unsafeElements: sharedSecretBuffer)
          try Parameters.decapsulate(
            Span(_unsafeElements: ciphertextBytes.bindMemory(to: UInt8.self)),
            using: box.privateKey,
            into: &sharedSecretSpan
          )
        }
      }
    } catch let error as SSLCrypto.KEMError {
      throw mapSSLCryptoKEMError(error)
    }
    return SymmetricKey(data: Data(sharedSecret))
  }
}

private func mapEntropyError(_ error: EntropyError) -> CryptoKitError {
  .invalidParameter
}

#endif
