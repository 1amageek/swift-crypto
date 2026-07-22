//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

internal import CCryptoBoringSSL
internal import CCryptoBoringSSLShims
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

internal struct BoringSSLScrypt {
    /// Derives a secure key using the provided passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation. Must be a power of 2.
    ///    - blockSize: The block size to be used by the algorithm.
    ///    - parallelism: The parallelism factor indicating how many threads should be run in parallel.
    /// - Returns: The derived symmetric key.
    static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(
        from password: Passphrase,
        salt: Salt,
        outputByteCount: Int,
        rounds: Int,
        blockSize: Int,
        parallelism: Int,
        maxMemory: Int? = nil
    ) throws(CryptoKitMetaError) -> SymmetricKey {
        guard
            outputByteCount > 0,
            outputByteCount <= Int.max / 8,
            rounds >= 2,
            rounds.isPowerOfTwo,
            UInt64(rounds) <= UInt64(1) << 32,
            blockSize > 0,
            parallelism > 0,
            parallelism <= ((1 << 30) - 1) / blockSize,
            blockSize > 3 || UInt64(rounds) < UInt64(1) << UInt64(16 * blockSize)
        else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }

        let requiredMemory = try self.requiredMemory(
            rounds: rounds,
            blockSize: blockSize,
            parallelism: parallelism
        )
        let memoryLimit = maxMemory ?? requiredMemory
        guard memoryLimit >= requiredMemory else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }

        #if canImport(CryptoKit)
        // The supported Apple 26 CryptoKit API has no caller-owned output initializer. This small,
        // explicitly zeroized handoff is the required copy at the system API boundary.
        var derivedKeyData = Data(count: outputByteCount)
        defer {
            derivedKeyData.withUnsafeMutableBytes { bytes in
                CCryptoBoringSSL_OPENSSL_cleanse(bytes.baseAddress, bytes.count)
            }
        }
        try derivedKeyData.withUnsafeMutableBytes { output in
            try self.deriveKeyBytes(
                from: password,
                salt: salt,
                rounds: rounds,
                blockSize: blockSize,
                parallelism: parallelism,
                memoryLimit: memoryLimit,
                output: output
            )
        }
        return SymmetricKey(data: derivedKeyData)
        #else
        return try SymmetricKey(
            unsafeUninitializedCapacity: outputByteCount
        ) {
            (
                output: inout UnsafeMutableRawBufferPointer,
                initializedByteCount: inout Int
            ) throws(CryptoKitMetaError) in
            try self.deriveKeyBytes(
                from: password,
                salt: salt,
                rounds: rounds,
                blockSize: blockSize,
                parallelism: parallelism,
                memoryLimit: memoryLimit,
                output: output
            )
            initializedByteCount = outputByteCount
        }
        #endif
    }

    private static func deriveKeyBytes<Passphrase: DataProtocol, Salt: DataProtocol>(
        from password: Passphrase,
        salt: Salt,
        rounds: Int,
        blockSize: Int,
        parallelism: Int,
        memoryLimit: Int,
        output: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError) {
        guard let outputAddress = output.baseAddress else {
            throw cryptoExtrasError(CryptoKitError.internalBoringSSLError())
        }
        try Crypto.withContiguousBytes(of: password) {
            (passwordBytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
            try Crypto.withContiguousBytes(of: salt) {
                (saltBytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                let result = CCryptoBoringSSL_EVP_PBE_scrypt(
                    passwordBytes.baseAddress,
                    passwordBytes.count,
                    saltBytes.baseAddress,
                    saltBytes.count,
                    UInt64(rounds),
                    UInt64(blockSize),
                    UInt64(parallelism),
                    memoryLimit,
                    outputAddress,
                    output.count
                )
                guard result == 1 else {
                    throw cryptoExtrasError(CryptoKitError.internalBoringSSLError())
                }
            }
        }
    }

    private static func requiredMemory(
        rounds: Int,
        blockSize: Int,
        parallelism: Int
    ) throws(CryptoKitMetaError) -> Int {
        let (parallelBlocks, parallelBlocksOverflow) = parallelism.addingReportingOverflow(1)
        let (blockCount, blockCountOverflow) = rounds.addingReportingOverflow(parallelBlocks)
        let (blockByteCount, blockByteCountOverflow) = blockSize.multipliedReportingOverflow(by: 128)
        let (requiredMemory, requiredMemoryOverflow) = blockByteCount.multipliedReportingOverflow(by: blockCount)
        guard
            !parallelBlocksOverflow,
            !blockCountOverflow,
            !blockByteCountOverflow,
            !requiredMemoryOverflow,
            requiredMemory > 0
        else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        return requiredMemory
    }
}

private extension Int {
    var isPowerOfTwo: Bool {
        self > 0 && (self & (self - 1)) == 0
    }
}
