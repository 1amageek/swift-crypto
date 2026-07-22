//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if hasFeature(Embedded)
import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif
import Crypto
import CryptoBoringWrapper

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
internal func cryptoExtrasError(_ error: CryptoKitError) -> CryptoKitMetaError {
    #if hasFeature(Embedded)
    return .cryptoKitError(underlyingError: error)
    #else
    return error
    #endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func cryptoExtrasError(_ error: CryptoKitASN1Error) -> CryptoKitMetaError {
    #if hasFeature(Embedded)
    return .asn1Error(underlyingError: error)
    #else
    return error
    #endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func cryptoExtrasError(_ error: CryptoBoringWrapperError) -> CryptoKitMetaError {
    #if !hasFeature(Embedded)
    return error
    #else
    let cryptoError: CryptoKitError
    switch error {
    case .incorrectKeySize:
        cryptoError = .incorrectKeySize
    case .incorrectParameterSize:
        cryptoError = .incorrectParameterSize
    case .authenticationFailure:
        cryptoError = .authenticationFailure
    case .underlyingCoreCryptoError(let errorCode):
        cryptoError = .underlyingCoreCryptoError(error: errorCode)
    case .wrapFailure:
        cryptoError = .wrapFailure
    case .unwrapFailure:
        cryptoError = .unwrapFailure
    case .invalidParameter:
        cryptoError = .incorrectParameterSize
    }
    return cryptoExtrasError(cryptoError)
    #endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func withCryptoExtrasError<Result>(
    _ body: () throws(CryptoKitError) -> Result
) throws(CryptoKitMetaError) -> Result {
    do {
        return try body()
    } catch {
        throw cryptoExtrasError(error)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func withCryptoExtrasBoringError<Result>(
    _ body: () throws(CryptoBoringWrapperError) -> Result
) throws(CryptoKitMetaError) -> Result {
    do {
        return try body()
    } catch {
        throw cryptoExtrasError(error)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func withCryptoExtrasInvalidParameter<Result, E: Error>(
    _ body: () throws(E) -> Result
) throws(CryptoKitMetaError) -> Result {
    #if hasFeature(Embedded)
    do throws(E) {
        return try body()
    } catch {
        throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
    }
    #else
    return try body()
    #endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
