//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// NOTE: This file is unconditionally compiled because RSABSSA is implemented using BoringSSL on all platforms.
#if hasFeature(Embedded)
import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif
#if hasFeature(Embedded)
import CCryptoBoringSSLShims
#else
@_implementationOnly import CCryptoBoringSSLShims
#endif
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
import Crypto
import CryptoBoringWrapper

func cryptoExtrasData<Bytes: Crypto.ContiguousBytes>(_ bytes: Bytes) -> Data {
    bytes.withUnsafeBytes { buffer in
        Data(buffer)
    }
}

extension ArbitraryPrecisionInteger {
    init<Bytes: Crypto.ContiguousBytes>(cryptoBytes bytes: Bytes) throws(CryptoKitMetaError) {
        #if hasFeature(Embedded)
        do {
            self = try bytes.withUnsafeBytes { (buffer) throws(CryptoBoringWrapperError) in
                try ArbitraryPrecisionInteger(bytes: buffer)
            }
        } catch {
            throw cryptoExtrasError(error)
        }
        #else
        self = try bytes.withUnsafeBytes { buffer in
            try ArbitraryPrecisionInteger(bytes: buffer)
        }
        #endif
    }
}

extension Data {
    init(
        cryptoExtrasBytesOf integer: ArbitraryPrecisionInteger,
        paddedToSize paddingSize: Int
    ) throws(CryptoKitMetaError) {
        do throws(CryptoBoringWrapperError) {
            let byteCount = integer.byteCount
            guard paddingSize >= byteCount else {
                throw CryptoBoringWrapperError.incorrectParameterSize
            }

            self.init(repeating: 0, count: paddingSize)
            let written = self.withUnsafeMutableBytes { bytes in
                let destination = UnsafeMutableRawBufferPointer(rebasing: bytes.suffix(byteCount))
                return integer.withUnsafeBignumPointer { integerPointer in
                    CCryptoBoringSSLShims_BN_bn2bin(integerPointer, destination.baseAddress!)
                }
            }
            assert(written == byteCount)
        } catch {
            throw cryptoExtrasError(error)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<ReturnValue, E: Error>(
        wrapping pointer: UnsafeRawBufferPointer, _ block: (OpaquePointer) throws(E) -> ReturnValue
    ) throws(E) -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<ReturnValue, E: Error>(
        wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (OpaquePointer) throws(E) -> ReturnValue
    ) throws(E) -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withWritableMemoryBIO<ReturnValue, E: Error>(_ block: (OpaquePointer) throws(E) -> ReturnValue) throws(E) -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem())!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    init(copyingMemoryBIO bio: OpaquePointer) throws(CryptoKitMetaError) {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw cryptoExtrasError(CryptoKitError.internalBoringSSLError())
        }

        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension String {
    init(copyingUTF8MemoryBIO bio: OpaquePointer) throws(CryptoKitMetaError) {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw cryptoExtrasError(CryptoKitError.internalBoringSSLError())
        }

        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension FixedWidthInteger {
    func withBignumPointer<ReturnType, E: Error>(_ block: (UnsafeMutablePointer<BIGNUM>) throws(E) -> ReturnType) throws(E) -> ReturnType {
        precondition(self.bitWidth <= UInt.bitWidth)

        var bn = BIGNUM()
        CCryptoBoringSSL_BN_init(&bn)
        defer {
            CCryptoBoringSSL_BN_clear(&bn)
        }

        CCryptoBoringSSL_BN_set_word(&bn, .init(self))

        return try block(&bn)
    }
}
