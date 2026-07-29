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

internal import CCryptoBoringSSL
import Crypto
import CryptoBoringWrapper

@usableFromInline
internal func cryptoExtrasError(_ error: CryptoKitError) -> CryptoKitMetaError {
    return error
}

internal func cryptoExtrasError(_ error: CryptoKitASN1Error) -> CryptoKitMetaError {
    return error
}

internal func cryptoExtrasError(_ error: CryptoBoringWrapperError) -> CryptoKitMetaError {
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
        cryptoError = .invalidParameter
    }
    return cryptoExtrasError(cryptoError)
}

internal func withCryptoExtrasError<Result>(
    _ body: () throws(CryptoKitError) -> Result
) throws(CryptoKitMetaError) -> Result {
    do {
        return try body()
    } catch {
        throw cryptoExtrasError(error)
    }
}

internal func withCryptoExtrasBoringError<Result>(
    _ body: () throws(CryptoBoringWrapperError) -> Result
) throws(CryptoKitMetaError) -> Result {
    do {
        return try body()
    } catch {
        throw cryptoExtrasError(error)
    }
}

internal func withCryptoExtrasInvalidParameter<Result, E: Error>(
    _ body: () throws(E) -> Result
) throws(CryptoKitMetaError) -> Result {
    return try body()
}

extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
