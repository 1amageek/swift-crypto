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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
import Crypto

/// Hashes a byte string into one or more finite-field elements.
struct HashToField<C: HashToGroupCurve> {
    private static func update(_ hasher: inout C.H, byte: UInt8) {
        var byte = byte
        withUnsafeBytes(of: &byte) { bytes in
            hasher.update(bufferPointer: bytes)
        }
    }

    private static func updateTwoByteInteger(
        _ hasher: inout C.H,
        value: Int
    ) throws(CryptoKitMetaError) {
        guard value >= 0, value <= Int(UInt16.max) else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        update(&hasher, byte: UInt8(truncatingIfNeeded: value >> 8))
        update(&hasher, byte: UInt8(truncatingIfNeeded: value))
    }

    private static func normalizedDomainSeparationTag(_ domainSeparationTag: Data) -> Data {
        guard domainSeparationTag.count > Int(UInt8.max) else {
            return domainSeparationTag
        }

        var hasher = C.H()
        hasher.update(data: Data("H2C-OVERSIZE-DST-".utf8))
        hasher.update(data: domainSeparationTag)
        return Data(hasher.finalize())
    }

    static func expandMessageXMD<Message: DataProtocol>(
        _ message: Message,
        DST domainSeparationTag: Data,
        outputByteCount: Int
    ) throws(CryptoKitMetaError) -> Data {
        try expandMessageXMD(
            DST: domainSeparationTag,
            outputByteCount: outputByteCount
        ) { hasher in
            hasher.update(data: message)
        }
    }

    private static func expandMessageXMD(
        DST domainSeparationTag: Data,
        outputByteCount: Int,
        updateInput: (inout C.H) throws(CryptoKitMetaError) -> Void
    ) throws(CryptoKitMetaError) -> Data {
        guard outputByteCount > 0, outputByteCount <= Int(UInt16.max) else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        var output = Data(count: outputByteCount)
        try output.withUnsafeMutableBytes {
            (destination: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try expandMessageXMD(
                DST: domainSeparationTag,
                into: destination,
                updateInput: updateInput
            )
        }
        return output
    }

    private static func expandMessageXMD(
        DST domainSeparationTag: Data,
        into output: UnsafeMutableRawBufferPointer,
        updateInput: (inout C.H) throws(CryptoKitMetaError) -> Void
    ) throws(CryptoKitMetaError) {
        typealias H = C.H
        let digestByteCount = H.Digest.byteCount
        let outputByteCount = output.count
        guard outputByteCount > 0, outputByteCount <= Int(UInt16.max) else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }

        let blockCount = (outputByteCount + digestByteCount - 1) / digestByteCount
        guard blockCount <= Int(UInt8.max) else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }

        let normalizedDomainSeparationTag = normalizedDomainSeparationTag(domainSeparationTag)
        guard normalizedDomainSeparationTag.count <= Int(UInt8.max) else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }

        var initialHasher = H()
        withUnsafeTemporaryAllocation(
            of: UInt8.self,
            capacity: H.blockByteCount
        ) { zeroPadding in
            zeroPadding.initialize(repeating: 0)
            initialHasher.update(bufferPointer: UnsafeRawBufferPointer(zeroPadding))
        }
        try updateInput(&initialHasher)
        try updateTwoByteInteger(&initialHasher, value: outputByteCount)
        update(&initialHasher, byte: 0)
        initialHasher.update(data: normalizedDomainSeparationTag)
        update(
            &initialHasher,
            byte: UInt8(normalizedDomainSeparationTag.count)
        )
        let initialDigest = initialHasher.finalize()

        var outputOffset = 0
        var previousDigest: H.Digest?
        for blockIndex in 1...blockCount {
            var blockHasher = H()
            if let previousDigest {
                withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: digestByteCount
                ) { chainingValue in
                    initialDigest.withUnsafeBytes { initialBytes in
                        previousDigest.withUnsafeBytes { previousBytes in
                            for index in 0..<digestByteCount {
                                chainingValue.initializeElement(
                                    at: index,
                                    to: initialBytes[index] ^ previousBytes[index]
                                )
                            }
                        }
                    }
                    blockHasher.update(
                        bufferPointer: UnsafeRawBufferPointer(chainingValue)
                    )
                }
            } else {
                initialDigest.withUnsafeBytes { bytes in
                    blockHasher.update(bufferPointer: bytes)
                }
            }

            update(&blockHasher, byte: UInt8(blockIndex))
            blockHasher.update(data: normalizedDomainSeparationTag)
            update(
                &blockHasher,
                byte: UInt8(normalizedDomainSeparationTag.count)
            )
            let digest = blockHasher.finalize()
            let remainingByteCount = outputByteCount - outputOffset
            let writeByteCount = Swift.min(
                remainingByteCount,
                digestByteCount
            )
            digest.withUnsafeBytes { bytes in
                let source = UnsafeRawBufferPointer(
                    rebasing: bytes.prefix(writeByteCount)
                )
                let destination = UnsafeMutableRawBufferPointer(
                    rebasing: output[outputOffset..<(outputOffset + writeByteCount)]
                )
                destination.copyMemory(from: source)
            }
            outputOffset += writeByteCount
            previousDigest = digest
        }
    }

    static func hashToField<Message: DataProtocol>(
        _ data: Message,
        outputElementCount: Int,
        dst: Data,
        outputSize: Int,
        reductionModulus: ScalarReductionModulus
    ) throws(CryptoKitMetaError) -> [PrimeOrderCurveGroup<C>.Scalar] {
        guard outputElementCount > 0 else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let (byteCount, overflow) = outputElementCount.multipliedReportingOverflow(
            by: outputSize
        )
        guard !overflow else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let uniformBytes = try expandMessageXMD(
            data,
            DST: dst,
            outputByteCount: byteCount
        )

        var elements: [PrimeOrderCurveGroup<C>.Scalar] = []
        elements.reserveCapacity(outputElementCount)
        for index in 0..<outputElementCount {
            let offset = index * outputSize
            let uniformElementBytes = uniformBytes[offset..<(offset + outputSize)]
            elements.append(
                try PrimeOrderCurveGroup<C>.Scalar.reducing(
                    uniformElementBytes,
                    modulo: reductionModulus
                )
            )
        }
        return elements
    }

    static func hashToFieldElement(
        dst: Data,
        reductionModulus: ScalarReductionModulus,
        updateInput: (inout C.H) throws(CryptoKitMetaError) -> Void
    ) throws(CryptoKitMetaError) -> PrimeOrderCurveGroup<C>.Scalar {
        try withUnsafeTemporaryAllocation(
            byteCount: C.hashToFieldByteCount,
            alignment: 1
        ) {
            (uniformBytes: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try expandMessageXMD(
                DST: dst,
                into: uniformBytes,
                updateInput: updateInput
            )
            return try PrimeOrderCurveGroup<C>.Scalar.reducing(
                UnsafeRawBufferPointer(uniformBytes),
                modulo: reductionModulus
            )
        }
    }
}
