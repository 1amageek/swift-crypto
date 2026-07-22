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
import CryptoKit
#else

// Swift 6.4 standard WASI has the same cross-module metadata defect for HMAC
// as it does for HashedAuthenticationCode. The nominal type must remain
// unconstrained there so public incremental HMAC values have valid metadata.
#if os(WASI) && !hasFeature(Embedded)
/// A hash-based message authentication algorithm.
///
/// Use hash-based message authentication to create a code with a value that’s
/// dependent on both a block of data and a symmetric cryptographic key. Another
/// party with access to the data and the same secret key can compute the code
/// again and compare it to the original to detect whether the data changed.
/// This serves a purpose similar to digital signing and verification, but
/// depends on a shared symmetric key instead of public-key cryptography.
///
/// As with digital signing, the data isn’t hidden by this process. When you
/// need to encrypt the data as well as authenticate it, use a cipher like
/// ``AES`` or ``ChaChaPoly`` to put the data into a sealed box (an instance of
/// ``AES/GCM/SealedBox`` or ``ChaChaPoly/SealedBox``).
public struct HMAC<H> {
    var outerHasher: H
    var innerHasher: H
}

extension HMAC: Sendable where H: HashFunction {}
extension HMAC: MACAlgorithm where H: HashFunction {}
#else
/// A hash-based message authentication algorithm.
///
/// Use hash-based message authentication to create a code with a value that’s
/// dependent on both a block of data and a symmetric cryptographic key. Another
/// party with access to the data and the same secret key can compute the code
/// again and compare it to the original to detect whether the data changed.
/// This serves a purpose similar to digital signing and verification, but
/// depends on a shared symmetric key instead of public-key cryptography.
///
/// As with digital signing, the data isn’t hidden by this process. When you
/// need to encrypt the data as well as authenticate it, use a cipher like
/// ``AES`` or ``ChaChaPoly`` to put the data into a sealed box (an instance of
/// ``AES/GCM/SealedBox`` or ``ChaChaPoly/SealedBox``).
public struct HMAC<H: HashFunction>: MACAlgorithm, Sendable {
    var outerHasher: H
    var innerHasher: H
}
#endif

extension HMAC where H: HashFunction {
    /// An alias for the symmetric key type used to compute or verify a message
    /// authentication code.
    public typealias Key = SymmetricKey
    /// An alias for a hash-based message authentication code.
    public typealias MAC = HashedAuthenticationCode<H>

    /// Returns a Boolean value indicating whether the given message
    /// authentication code is valid for a block of data stored in a buffer.
    ///
    /// - Parameters:
    ///   - mac: The authentication code to compare.
    ///   - bufferPointer: A pointer to the block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the data within the specified buffer.
    public static func isValidAuthenticationCode(
        _ mac: MAC,
        authenticating bufferPointer: UnsafeRawBufferPointer,
        using key: SymmetricKey
    ) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: mac, authenticatedData: bufferPointer, key: key)
    }

    /// Creates a message authentication code generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    public init(key: SymmetricKey) {
        self.init(keyMaterial: key.bytes)
    }

    init<KeyMaterial: DataProtocol>(keyMaterial: KeyMaterial) {
        self.init(
            keyByteCount: keyMaterial.count,
            appendKeyMaterial: { output in
                for region in keyMaterial.regions {
                    region.withUnsafeBytes { buffer in
                        output.append(contentsOf: buffer.bytes)
                    }
                }
            },
            hashKeyMaterial: { hasher in
                hasher.update(data: keyMaterial)
            }
        )
    }

    init(keyMaterial: RawSpan) {
        self.init(
            keyByteCount: keyMaterial.byteCount,
            appendKeyMaterial: { output in
                output.append(contentsOf: keyMaterial)
            },
            hashKeyMaterial: { hasher in
                hasher.update(bytes: keyMaterial)
            }
        )
    }

    private init(
        keyByteCount: Int,
        appendKeyMaterial: (inout OutputRawSpan) -> Void,
        hashKeyMaterial: (inout H) -> Void
    ) {
        precondition(keyByteCount >= 0)
        precondition(H.blockByteCount > 0)
        let digestByteCount = H.Digest.byteCount
        precondition(digestByteCount > 0)
        precondition(digestByteCount <= H.blockByteCount)
        var keyBlock = SecureBytes(capacity: H.blockByteCount) { keyOutput in
            if keyByteCount <= H.blockByteCount {
                appendKeyMaterial(&keyOutput)
            } else {
                var hasher = H()
                hashKeyMaterial(&hasher)
                let hash = hasher.finalize()
                hash.withUnsafeBytes { buffer in
                    keyOutput.append(contentsOf: buffer.bytes)
                }
            }
            keyOutput.append(repeating: 0, count: keyOutput.freeCapacity, as: UInt8.self)
        }

        self.innerHasher = H()
        keyBlock.withUnsafeMutableBytes {
            for i in 0 ..< $0.count {
                $0[i] ^= 0x36
            }
        }
        innerHasher.update(bytes: keyBlock.bytes)

        self.outerHasher = H()
        keyBlock.withUnsafeMutableBytes {
            for i in 0 ..< $0.count {
                $0[i] ^= 0x36 ^ 0x5c
            }
        }
        outerHasher.update(bytes: keyBlock.bytes)
    }

    /// Computes a message authentication code for the given data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    ///   - key: The symmetric key used to secure the computation.
    ///
    /// - Returns: The message authentication code.
    public static func authenticationCode<D: DataProtocol>(
        for data: D,
        using key: SymmetricKey
    ) -> MAC {
        var authenticator = Self(key: key)
        authenticator.update(data: data)
        return authenticator.finalizeAuthenticationCode()
    }

    /// Computes a message authentication code for the given data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    ///   - key: The symmetric key used to secure the computation.
    ///
    /// - Returns: The message authentication code.
    public static func authenticationCode(for data: RawSpan, using key: SymmetricKey) -> MAC {
        var authenticator = Self(key: key)
        authenticator.update(bytes: data)
        return authenticator.finalizeAuthenticationCode()
    }

    /// Returns a Boolean value indicating whether the given message
    /// authentication code is valid for a block of data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code to compare.
    ///   - authenticatedData: The block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the specified block of data.
    public static func isValidAuthenticationCode<D: DataProtocol>(
        _ authenticationCode: MAC,
        authenticating authenticatedData: D,
        using key: SymmetricKey
    ) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }

    /// Returns a Boolean value indicating whether the given message
    /// authentication code represented as contiguous bytes is valid for a block
    /// of data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code to compare.
    ///   - authenticatedData: The block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the specified block of data.
    public static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(
        _ authenticationCode: C,
        authenticating authenticatedData: D,
        using key: SymmetricKey
    ) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }

    /// Updates the message authentication code computation with a block of
    /// data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    public mutating func update<D: DataProtocol>(data: D) {
        data.regions.forEach { (memoryRegion) in
            memoryRegion.withUnsafeBytes({ (bp) in
                self.update(bufferPointer: bp)
            })
        }
    }

    public mutating func update(bytes: RawSpan) {
        innerHasher.update(bytes: bytes)
    }

    /// Finalizes the message authentication computation and returns the
    /// computed code.
    ///
    /// - Returns: The message authentication code.
    public func finalize() -> MAC {
        let innerHash = innerHasher.finalize()
        var outerHashForFinalization = outerHasher
        innerHash.withUnsafeBytes { buffer in
            outerHashForFinalization.update(bufferPointer: buffer)
        }
        return HashedAuthenticationCode(
            digest: outerHashForFinalization.finalize()
        )
    }

    mutating func finalizeAuthenticationCode() -> MAC {
        HashedAuthenticationCode(
            digest: finalizeDigest()
        )
    }

    mutating func withFinalizedDigestBytes<Result>(
        _ body: (UnsafeRawBufferPointer) -> Result
    ) -> Result {
        let digest = finalizeDigest()
        return digest.withUnsafeBytes(body)
    }

    private mutating func finalizeDigest() -> H.Digest {
        let innerHash = innerHasher.finalize()
        innerHash.withUnsafeBytes { buffer in
            outerHasher.update(bufferPointer: buffer)
        }
        return outerHasher.finalize()
    }

    /// Adds data to be authenticated by MAC function. This can be called one or more times to append additional data.
    ///
    /// - Parameters:
    ///   - data: The data to be authenticated.
    /// - Throws: Throws if the HMAC has already been finalized.
    mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        innerHasher.update(bufferPointer: bufferPointer)
    }

    /// A common implementation of isValidAuthenticationCode shared by the various entry points.
    private static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(
        authenticationCodeBytes: C,
        authenticatedData: D,
        key: SymmetricKey
    ) -> Bool {
        var authenticator = Self(key: key)
        authenticator.update(data: authenticatedData)
        return authenticator.withFinalizedDigestBytes { computedCodeBytes in
            safeCompare(authenticationCodeBytes, computedCodeBytes)
        }
    }

    private static func isValidAuthenticationCode<C: ContiguousBytes>(
        authenticationCodeBytes: C,
        authenticatedData: UnsafeRawBufferPointer,
        key: SymmetricKey
    ) -> Bool {
        var authenticator = Self(key: key)
        authenticator.update(bufferPointer: authenticatedData)
        return authenticator.withFinalizedDigestBytes { computedCodeBytes in
            safeCompare(authenticationCodeBytes, computedCodeBytes)
        }
    }
}

#if os(WASI) && !hasFeature(Embedded)
// Swift 6.4 mis-emits associated-type witnesses for a constrained generic
// nominal type across module boundaries on standard WASI. Keeping the nominal
// type unconstrained and expressing its requirements as conditional
// conformances gives the runtime valid witness metadata.
/// A hash-based message authentication code.
public struct HashedAuthenticationCode<H> {
    // Internal HMAC and HKDF paths borrow the finalized digest directly. Only
    // the public owned result is materialized once so its byte view has a
    // stable lifetime after the digest leaves the finalization scope.
    let bytes: SecureBytes

    init(digest: H.Digest) where H: HashFunction {
        self.bytes = digest.withUnsafeBytes { buffer in
            SecureBytes(bytes: buffer.bytes)
        }
    }
}

extension HashedAuthenticationCode: Sendable where H: HashFunction {}

extension HashedAuthenticationCode: Equatable where H: HashFunction {
    public static func == (
        lhs: HashedAuthenticationCode<H>,
        rhs: HashedAuthenticationCode<H>
    ) -> Bool {
        safeCompare(lhs, rhs)
    }
}

extension HashedAuthenticationCode: Hashable where H: HashFunction {
    public func hash(into hasher: inout Hasher) {
        bytes.withUnsafeBytes { buffer in
            hasher.combine(bytes: buffer)
        }
    }
}

extension HashedAuthenticationCode: ContiguousBytes where H: HashFunction {
    public func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
}

extension HashedAuthenticationCode: Sequence where H: HashFunction {
    public typealias Element = UInt8
    public typealias Iterator = Array<UInt8>.Iterator

    public func makeIterator() -> Iterator {
        bytes.withUnsafeBytes { buffer in
            Array(buffer.bindMemory(to: UInt8.self)).makeIterator()
        }
    }

    public __consuming func _copyToContiguousArray() -> ContiguousArray<UInt8> {
        bytes.withUnsafeBytes { buffer in
            ContiguousArray(buffer.bindMemory(to: UInt8.self))
        }
    }
}

extension HashedAuthenticationCode: CustomStringConvertible where H: HashFunction {
    public var description: String {
        bytes.withUnsafeBytes { buffer in
            "HMAC with \(H.self): \(Array(buffer).hexString)"
        }
    }
}

extension HashedAuthenticationCode: MessageAuthenticationCode where H: HashFunction {
    /// The number of bytes in the message authentication code.
    public var byteCount: Int {
        bytes.count
    }
}

extension SymmetricKey {
    // SecureBytes uses copy-on-write storage, so this specialized initializer
    // avoids materializing the owned authentication code a second time.
    /// Creates a symmetric key from a hash-based message authentication code.
    public init<H: HashFunction>(data authenticationCode: HashedAuthenticationCode<H>) {
        self.init(data: authenticationCode.bytes)
    }
}
#else
/// A hash-based message authentication code.
public struct HashedAuthenticationCode<H: HashFunction>: MessageAuthenticationCode, Sendable {
    let digest: H.Digest

    init(digest: H.Digest) {
        self.digest = digest
    }

    /// The number of bytes in the message authentication code.
    public var byteCount: Int {
        return H.Digest.byteCount
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the code.
    public var description: String {
        return "HMAC with \(H.self): \(Array(digest).hexString)"
    }
#endif

    /// Invokes the given closure with a buffer pointer covering the raw bytes
    /// of the code.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the
    /// code and returns the code.
    ///
    /// - Returns: The code, as returned from the body closure.
    #if hasFeature(Embedded)
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try digest.withUnsafeBytes(body)
    }
    #else
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try digest.withUnsafeBytes(body)
    }
    #endif
}
#endif
#endif // canImport(CryptoKit)
