//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//


#if !canImport(CryptoKit) && !canImport(FoundationEssentials) && !canImport(Foundation)
import CryptoBoringWrapper
internal import CCryptoBoringSSLShims

extension Data: CryptoBoringWrapper.ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        self.storage.withUnsafeBytes { buffer in
            body(UnsafeRawBufferPointer(rebasing: buffer[self.storageRange]))
        }
    }

    public func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R
    ) throws(CryptoBoringWrapperError) -> R {
        try self.storage.withUnsafeBytes { buffer throws(CryptoBoringWrapperError) in
            try body(UnsafeRawBufferPointer(rebasing: buffer[self.storageRange]))
        }
    }
}

extension Data {
    @usableFromInline
    mutating func append(
        bytesOf integer: ArbitraryPrecisionInteger,
        paddedToSize paddingSize: Int
    ) throws(CryptoBoringWrapperError) {
        let byteCount = integer.byteCount

        guard paddingSize >= byteCount else {
            throw CryptoBoringWrapperError.incorrectParameterSize
        }

        self.append(contentsOf: repeatElement(UInt8(0), count: paddingSize))

        let written: Int = self.withUnsafeMutableBytes { bytesPtr in
            let bytesPtr = UnsafeMutableRawBufferPointer(rebasing: bytesPtr.suffix(byteCount))
            return integer.withUnsafeBignumPointer { bnPtr in
                CCryptoBoringSSLShims_BN_bn2bin(bnPtr, bytesPtr.baseAddress!)
            }
        }

        assert(written == byteCount)
    }

    @usableFromInline
    init(bytesOf integer: ArbitraryPrecisionInteger, paddedToSize paddingSize: Int) throws(CryptoBoringWrapperError) {
        self.init()
        self.reserveCapacity(paddingSize)
        try self.append(bytesOf: integer, paddedToSize: paddingSize)
    }
}
#endif
