#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto

enum SSLCryptoAESWRAPImpl {
  static func wrap(
    key: SymmetricKey,
    keyToWrap: SymmetricKey
  ) throws(CryptoKitMetaError) -> Data {
    var output = ContiguousArray<UInt8>(repeating: 0, count: keyToWrap.byteCount + 8)
    try key.withUnsafeBytes { keyBytes in
      try keyToWrap.withUnsafeBytes { plaintextBytes in
        let keySpan = Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self))
        let plaintextSpan = Span(_unsafeElements: plaintextBytes.bindMemory(to: UInt8.self))
        try output.withUnsafeMutableBufferPointer { outputBuffer in
          var outputSpan = MutableSpan(_unsafeElements: outputBuffer)
          do {
            try SSLCrypto.AESKeyWrap.wrap(
              key: keySpan,
              plaintext: plaintextSpan,
              into: &outputSpan
            )
          } catch let error as AESKeyWrapError {
            throw map(error)
          }
        }
      }
    }
    return Data(output)
  }

  static func unwrap<WrappedKey: DataProtocol>(
    key: SymmetricKey,
    wrappedKey: WrappedKey
  ) throws(CryptoKitMetaError) -> SymmetricKey {
    var wrapped = Data()
    wrapped.reserveCapacity(wrappedKey.count)
    for region in wrappedKey.regions {
      region.withUnsafeBytes { bytes in
        wrapped.append(contentsOf: bytes)
      }
    }

    guard wrapped.count >= SSLCrypto.AESKeyWrap.overhead else {
      throw CryptoKitError.unwrapFailure
    }
    var output = ContiguousArray<UInt8>(repeating: 0, count: wrapped.count - SSLCrypto.AESKeyWrap.overhead)
    try key.withUnsafeBytes { keyBytes in
      try wrapped.withUnsafeBytes { wrappedBytes in
        let keySpan = Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self))
        let wrappedSpan = Span(_unsafeElements: wrappedBytes.bindMemory(to: UInt8.self))
        try output.withUnsafeMutableBufferPointer { outputBuffer in
          var outputSpan = MutableSpan(_unsafeElements: outputBuffer)
          do {
            try SSLCrypto.AESKeyWrap.unwrap(
              key: keySpan,
              wrapped: wrappedSpan,
              into: &outputSpan
            )
          } catch let error as AESKeyWrapError {
            throw map(error)
          }
        }
      }
    }
    return SymmetricKey(data: Data(output))
  }

  private static func map(_ error: AESKeyWrapError) -> CryptoKitError {
    switch error {
    case .invalidKeyLength, .invalidInputLength, .invalidOutputLength:
      return .incorrectParameterSize
    case .integrityFailure:
      return .unwrapFailure
    }
  }
}

#endif
