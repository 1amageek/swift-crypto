//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
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
@_exported import CryptoKit
#else
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
import CryptoBoringWrapper

/// A wrapper around BoringSSL's ECDSA_SIG with some lifetime management.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
final class ECDSASignature {
    private var _baseSig: UnsafeMutablePointer<ECDSA_SIG>

    init(contiguousDERBytes derBytes: Data) throws(CryptoBoringWrapperError) {
        self._baseSig = try withCryptoUnsafeBytes(derBytes) { (bytesPtr) throws(CryptoBoringWrapperError) in
            guard
                let sig = CCryptoBoringSSLShims_ECDSA_SIG_from_bytes(bytesPtr.baseAddress, bytesPtr.count)
            else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            return sig
        }
    }

    @usableFromInline
    init(rawRepresentation: Data) throws(CryptoBoringWrapperError) {
        let half = rawRepresentation.count / 2
        let r = try ArbitraryPrecisionInteger(bytes: Data(rawRepresentation.prefix(half)))
        let s = try ArbitraryPrecisionInteger(bytes: Data(rawRepresentation.suffix(half)))
        guard let sig = CCryptoBoringSSL_ECDSA_SIG_new() else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        self._baseSig = sig

        try r.withUnsafeBignumPointer { (rPtr) throws(CryptoBoringWrapperError) in
            try s.withUnsafeBignumPointer { (sPtr) throws(CryptoBoringWrapperError) in
                // This call is awkward: on success it _takes ownership_ of both values, on failure it doesn't.
                // This means we need to dup the pointers (to get something the ECDSA_SIG can own) and then
                // on error we have to free them. This makes lifetime management pretty rough here!
                guard let rCopy = CCryptoBoringSSL_BN_dup(rPtr) else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
                guard let sCopy = CCryptoBoringSSL_BN_dup(sPtr) else {
                    CCryptoBoringSSL_BN_free(rCopy)
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }

                let rc = CCryptoBoringSSL_ECDSA_SIG_set0(self._baseSig, rCopy, sCopy)
                if rc == 0 {
                    // Error. We still own the bignums, and must free them.
                    CCryptoBoringSSL_BN_free(rCopy)
                    CCryptoBoringSSL_BN_free(sCopy)
                }

                // Success. We don't own the bignums anymore and mustn't free them.
            }
        }
    }

    init(takingOwnershipOf pointer: UnsafeMutablePointer<ECDSA_SIG>) {
        self._baseSig = pointer
    }

    deinit {
        CCryptoBoringSSL_ECDSA_SIG_free(self._baseSig)
    }

    @usableFromInline
    var components: (r: ArbitraryPrecisionInteger, s: ArbitraryPrecisionInteger) {
        var rPtr: UnsafePointer<BIGNUM>?
        var sPtr: UnsafePointer<BIGNUM>?

        // We force-unwrap here because a valid ECDSA_SIG cannot fail to have both R and S components.
        CCryptoBoringSSL_ECDSA_SIG_get0(self._baseSig, &rPtr, &sPtr)
        return (
            r: try! ArbitraryPrecisionInteger(copying: rPtr!),
            s: try! ArbitraryPrecisionInteger(copying: sPtr!)
        )
    }

    @usableFromInline
    var derBytes: Data {
        var dataPtr: UnsafeMutablePointer<UInt8>?
        var length = 0
        guard CCryptoBoringSSL_ECDSA_SIG_to_bytes(&dataPtr, &length, self._baseSig) == 1 else {
            fatalError("Unable to marshal signature to DER")
        }
        defer {
            // We must free this pointer.
            CCryptoBoringSSL_OPENSSL_free(dataPtr)
        }

        return Data(UnsafeBufferPointer(start: dataPtr, count: length))
    }

    func withUnsafeSignaturePointer<T, E: Error>(
        _ body: (UnsafeMutablePointer<ECDSA_SIG>) throws(E) -> T
    )
        throws(E) -> T
    {
        try body(self._baseSig)
    }
}
#endif  // canImport(CryptoKit)
