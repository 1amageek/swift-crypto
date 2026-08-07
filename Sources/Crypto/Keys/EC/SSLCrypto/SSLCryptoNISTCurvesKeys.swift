//===----------------------------------------------------------------------===//
//
// Pure Swift NIST curve adapters for the CryptoKit-compatible facade.
//
// The adapter owns only the facade's value boundary. Secret scalar storage is
// wiped by `SecureBytes`; SSLCrypto keys are reconstructed inside a scoped
// borrow and never escape the operation that consumes them.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto

private func mapSSLCryptoNISTError(_ error: CryptoInputError) -> CryptoKitError {
    switch error {
    case .invalidLength, .invalidOutputLength:
        return .incorrectParameterSize
    case .nonCanonicalEncoding, .invalidPeerKey, .invalidSignature, .invalidRange,
         .contextTooLong, .inputTooLong:
        return .invalidParameter
    }
}

private func copyContiguousBytes<D: ContiguousBytes>(_ data: D) -> [UInt8] {
    data.withUnsafeBytes { Array($0) }
}

private func nistCoordinateByteCount<Curve>(for curve: Curve.Type) -> Int? {
    if curve == P256.self { return 32 }
    if curve == P384.self { return 48 }
    if curve == P521.self { return 66 }
    return nil
}

struct SSLCryptoNISTCurvePublicKeyImpl<Curve>: Sendable {
    let x963Bytes: [UInt8]

    init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitError) {
        let raw = copyContiguousBytes(rawRepresentation)
        guard let coordinateByteCount = nistCoordinateByteCount(for: Curve.self) else {
            throw .invalidParameter
        }
        guard raw.count == coordinateByteCount * 2 else { throw .incorrectParameterSize }
        var x963 = [UInt8](repeating: 0x04, count: 1 + raw.count)
        x963.replaceSubrange(1..<x963.count, with: raw)
        try self.init(validatedX963: x963)
    }

    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitError) {
        let compact = copyContiguousBytes(compactRepresentation)
        guard let coordinateByteCount = nistCoordinateByteCount(for: Curve.self) else {
            throw .invalidParameter
        }
        guard compact.count == coordinateByteCount else { throw .incorrectParameterSize }

        var compressed = [UInt8](repeating: 0, count: coordinateByteCount + 1)
        compressed.replaceSubrange(1..<compressed.count, with: compact)
        compressed[0] = 0x02
        let evenRoot = try Self(compressedRepresentation: compressed)
        compressed[0] = 0x03
        let oddRoot = try Self(compressedRepresentation: compressed)
        let yStart = coordinateByteCount + 1
        let evenY = evenRoot.x963Bytes[yStart...]
        let oddY = oddRoot.x963Bytes[yStart...]

        // The compact-point representation selects the numerically smaller
        // square root, so the X coordinate determines exactly one point.
        self = oddY.lexicographicallyPrecedes(evenY) ? oddRoot : evenRoot
    }

    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitError) {
        try self.init(validatedX963: copyContiguousBytes(x963Representation))
    }

    init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitError) {
        let compressed = copyContiguousBytes(compressedRepresentation)
        do {
            if Curve.self == P256.self {
                let key = try compressed.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P256PublicKey(
                        compressedBytes: Span(_unsafeElements: raw)
                    )
                }
                self.x963Bytes = Array(copying: key.span.bytes)
                return
            }
            if Curve.self == P384.self {
                let key = try compressed.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P384PublicKey(
                        compressedBytes: Span(_unsafeElements: raw)
                    )
                }
                self.x963Bytes = Array(copying: key.span.bytes)
                return
            }
            if Curve.self == P521.self {
                let key = try compressed.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P521PublicKey(
                        compressedBytes: Span(_unsafeElements: raw)
                    )
                }
                self.x963Bytes = Array(copying: key.span.bytes)
                return
            }
            throw CryptoKitError.invalidParameter
        } catch let error as CryptoInputError {
            throw mapSSLCryptoNISTError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw .invalidParameter
        }
    }

    init(validatedX963 bytes: [UInt8]) throws(CryptoKitError) {
        if Curve.self == P384.self {
            guard bytes.count == SSLCrypto.P384PublicKey.uncompressedByteCount,
                  bytes.first == 0x04 else { throw .incorrectParameterSize }
            do {
                let key = try bytes.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P384PublicKey(bytes: Span(_unsafeElements: raw))
                }
                self.x963Bytes = Array(copying: key.span.bytes)
                return
            } catch let error as CryptoInputError {
                throw mapSSLCryptoNISTError(error)
            } catch {
                throw .invalidParameter
            }
        }
        if Curve.self == P521.self {
            guard bytes.count == SSLCrypto.P521PublicKey.uncompressedByteCount,
                  bytes.first == 0x04 else { throw .incorrectParameterSize }
            do {
                let key = try bytes.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P521PublicKey(bytes: Span(_unsafeElements: raw))
                }
                self.x963Bytes = Array(copying: key.span.bytes)
                return
            } catch let error as CryptoInputError {
                throw mapSSLCryptoNISTError(error)
            } catch {
                throw .invalidParameter
            }
        }
        guard bytes.count == SSLCrypto.P256PublicKey.uncompressedByteCount,
              bytes.first == 0x04 else {
            throw .incorrectParameterSize
        }
        do {
            let key = try bytes.withUnsafeBufferPointer { raw in
                try SSLCrypto.P256PublicKey(
                    bytes: Span(_unsafeElements: raw)
                )
            }
            self.x963Bytes = Array(copying: key.span.bytes)
        } catch let error as CryptoInputError {
            throw mapSSLCryptoNISTError(error)
        } catch {
            throw .invalidParameter
        }
    }

    var compactRepresentation: Data? {
        guard let coordinateByteCount = nistCoordinateByteCount(for: Curve.self) else {
            preconditionFailure("Unsupported Pure Swift NIST curve")
        }
        var alternateCompressed = [UInt8](compressedRepresentation)
        alternateCompressed[0] ^= 0x01
        do {
            let alternate = try Self(compressedRepresentation: alternateCompressed)
            let yStart = coordinateByteCount + 1
            let currentY = x963Bytes[yStart...]
            let alternateY = alternate.x963Bytes[yStart...]
            guard !alternateY.lexicographicallyPrecedes(currentY) else { return nil }
            return Data(x963Bytes[1...coordinateByteCount])
        } catch {
            preconditionFailure("Validated Pure Swift NIST public key became invalid")
        }
    }

    var rawRepresentation: Data { Data(x963Bytes.dropFirst()) }

    var x963Representation: Data { Data(x963Bytes) }

    var compressedRepresentation: Data {
        do {
            if Curve.self == P384.self {
                let key = try x963Bytes.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P384PublicKey(bytes: Span(_unsafeElements: raw))
                }
                return Data(key.compressedBytes())
            }
            if Curve.self == P521.self {
                let key = try x963Bytes.withUnsafeBufferPointer { raw in
                    try SSLCrypto.P521PublicKey(bytes: Span(_unsafeElements: raw))
                }
                return Data(key.compressedBytes())
            }
            let key = try x963Bytes.withUnsafeBufferPointer { raw in
                try SSLCrypto.P256PublicKey(bytes: Span(_unsafeElements: raw))
            }
            return Data(key.compressedBytes())
        } catch {
            preconditionFailure("Validated Pure Swift NIST public key became invalid")
        }
    }
}

struct SSLCryptoNISTCurvePrivateKeyImpl<Curve>: Sendable {
    var key: SecureBytes
    var publicKeyStorage: SSLCryptoNISTCurvePublicKeyImpl<Curve>

    init(compactRepresentable: Bool = true) {
        do {
            for _ in 0..<100 {
                let generated = try Self.generateKeyMaterial()
                if !compactRepresentable || generated.publicKey.compactRepresentation != nil {
                    key = generated.key
                    publicKeyStorage = generated.publicKey
                    return
                }
            }
            preconditionFailure("Unable to generate a compact-representable Pure Swift NIST key")
        } catch {
            preconditionFailure("Unable to generate a Pure Swift NIST key: \(error)")
        }
    }

    init<Bytes: ContiguousBytes>(x963: Bytes) throws(CryptoKitError) {
        let bytes = copyContiguousBytes(x963)
        let coordinateByteCount: Int
        if Curve.self == P256.self { coordinateByteCount = 32 }
        else if Curve.self == P384.self { coordinateByteCount = 48 }
        else if Curve.self == P521.self { coordinateByteCount = 66 }
        else { throw .invalidParameter }
        let expectedCount = 1 + (coordinateByteCount * 3)
        guard bytes.count == expectedCount, bytes.first == 0x04 else {
            throw .incorrectParameterSize
        }
        let scalar = Array(bytes.suffix(coordinateByteCount))
        do {
            let publicBytes = try Self.derivePublicBytes(fromScalar: scalar)
            let publicKey = try Self.makePublicKey(fromX963: publicBytes)
            guard Array(bytes[1..<(1 + coordinateByteCount * 2)])
                    == Array(publicKey.x963Bytes[1..<(1 + coordinateByteCount * 2)]) else {
                throw CryptoKitError.invalidParameter
            }
            key = SecureBytes(bytes: scalar)
            publicKeyStorage = publicKey
        } catch let error as CryptoInputError {
            throw mapSSLCryptoNISTError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw .invalidParameter
        }
    }

    init<Bytes: ContiguousBytes>(data: Bytes) throws(CryptoKitError) {
        let scalar = copyContiguousBytes(data)
        let expectedCount: Int
        if Curve.self == P256.self { expectedCount = 32 }
        else if Curve.self == P384.self { expectedCount = 48 }
        else if Curve.self == P521.self { expectedCount = 66 }
        else { throw .invalidParameter }
        guard scalar.count == expectedCount else { throw .incorrectParameterSize }
        do {
            let publicBytes = try Self.derivePublicBytes(fromScalar: scalar)
            key = SecureBytes(bytes: scalar)
            publicKeyStorage = try Self.makePublicKey(fromX963: publicBytes)
        } catch let error as CryptoInputError {
            throw mapSSLCryptoNISTError(error)
        } catch {
            throw .invalidParameter
        }
    }

    func publicKey() -> SSLCryptoNISTCurvePublicKeyImpl<Curve> {
        publicKeyStorage
    }

    var rawRepresentation: Data {
        key.bytes.withUnsafeBytes { raw in
            guard let baseAddress = raw.baseAddress else { return Data() }
            return Data(bytes: baseAddress, count: raw.count)
        }
    }

    var x963Representation: Data {
        var bytes = publicKeyStorage.x963Bytes
        bytes.append(contentsOf: Array(copying: key.bytes))
        return Data(bytes)
    }

    private static func derivePublicBytes(fromScalar scalar: [UInt8]) throws -> [UInt8] {
        try scalar.withUnsafeBufferPointer { raw in
            if Curve.self == P256.self {
                let generated = try SSLCrypto.P256PrivateKey(
                    bytes: Span(_unsafeElements: raw)
                )
                return Array(copying: generated.publicKey().span.bytes)
            }
            if Curve.self == P384.self {
                let generated = try SSLCrypto.P384PrivateKey(
                    bytes: Span(_unsafeElements: raw)
                )
                return Array(copying: generated.publicKey().span.bytes)
            }
            if Curve.self == P521.self {
                let generated = try SSLCrypto.P521PrivateKey(
                    bytes: Span(_unsafeElements: raw)
                )
                return Array(copying: generated.publicKey().span.bytes)
            }
            throw CryptoInputError.invalidRange
        }
    }

    private static func generateKeyMaterial() throws -> (
        key: SecureBytes,
        publicKey: SSLCryptoNISTCurvePublicKeyImpl<Curve>
    ) {
        let raw: [UInt8]
        let publicBytes: [UInt8]
        if Curve.self == P256.self {
            let generated = try SSLCrypto.P256PrivateKey.generate()
            raw = generated.withBorrowedBytes { bytes in
                bytes.withUnsafeBytes { Array($0) }
            }
            publicBytes = Array(copying: generated.publicKey().span.bytes)
        } else if Curve.self == P384.self {
            let generated = try SSLCrypto.P384PrivateKey.generate()
            raw = generated.withBorrowedBytes { bytes in
                bytes.withUnsafeBytes { Array($0) }
            }
            publicBytes = Array(copying: generated.publicKey().span.bytes)
        } else if Curve.self == P521.self {
            let generated = try SSLCrypto.P521PrivateKey.generate()
            raw = generated.withBorrowedBytes { bytes in
                bytes.withUnsafeBytes { Array($0) }
            }
            publicBytes = Array(copying: generated.publicKey().span.bytes)
        } else {
            throw CryptoInputError.invalidRange
        }
        return (
            SecureBytes(bytes: raw),
            try Self.makePublicKey(fromX963: publicBytes)
        )
    }

    private static func makePublicKey(
        fromX963 publicBytes: [UInt8]
    ) throws(CryptoKitError) -> SSLCryptoNISTCurvePublicKeyImpl<Curve> {
        try SSLCryptoNISTCurvePublicKeyImpl<Curve>(validatedX963: publicBytes)
    }
}

#endif
