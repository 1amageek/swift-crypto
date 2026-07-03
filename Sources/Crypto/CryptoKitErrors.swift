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


#if canImport(CryptoKit)
@_exported import CryptoKit
#else
import CryptoBoringWrapper

/// General cryptography errors used by CryptoKit.
@nonexhaustive
public enum CryptoKitError: Error {
    /// The key size is incorrect.
    case incorrectKeySize
    /// The parameter size is incorrect.
    case incorrectParameterSize
    /// The authentication tag or signature is incorrect.
    case authenticationFailure
    /// The underlying corecrypto library is unable to complete the requested
    /// action.
    case underlyingCoreCryptoError(error: Int32)
    /// The framework can't wrap the specified key.
    case wrapFailure
    /// The framework can't unwrap the specified key.
    case unwrapFailure
    /// The parameter is invalid.
    case invalidParameter
}

extension CryptoKitError: Equatable, Hashable {}

/// Errors from decoding ASN.1 content.
@nonexhaustive
public enum CryptoKitASN1Error: Equatable, Error, Hashable {
    /// The ASN.1 tag for this field is invalid or unsupported.
    case invalidFieldIdentifier

    /// The ASN.1 tag for the parsed field doesn’t match the required format.
    case unexpectedFieldType

    /// An ASN.1 object identifier is invalid.
    case invalidObjectIdentifier

    /// The format of the parsed ASN.1 object doesn’t match the format required
    /// for the data type being decoded.
    case invalidASN1Object

    /// An ASN.1 integer doesn’t use the minimum number of bytes for its
    /// encoding.
    case invalidASN1IntegerEncoding

    /// An ASN.1 field is truncated.
    case truncatedASN1Field

    /// The encoding used for the field length is unsupported.
    case unsupportedFieldLength

    /// The string doesn’t parse as a PEM document.
    case invalidPEMDocument
}

enum RSAPSSSPKIErrors: Error {
    case invalidPSSOID
    case missingParameters
    case incorrectHashFunction
    case incorrectMGF
    case missingMGFHashFunction
    case incorrectMGFHashFunction
    case invalidSaltLength
}

#if hasFeature(Embedded)
public struct RSAPSSSPKIError: Error {
    internal var error: RSAPSSSPKIErrors
}
#else
struct RSAPSSSPKIError: Error {
    internal var error: RSAPSSSPKIErrors
}
#endif

#if hasFeature(Embedded)
@nonexhaustive
public enum CryptoKitMetaError: Error {
    case cryptoKitError(underlyingError: CryptoKitError)
    case asn1Error(underlyingError: CryptoKitASN1Error)
    case hpkeError(underlyingError: HPKE.Errors)
    case kemError(underlyingError: KEM.Errors)
    case rsapssspkiError(underlyingError: RSAPSSSPKIError)
}

@usableFromInline
internal func error(_ error: CryptoKitError) -> CryptoKitMetaError {
    .cryptoKitError(underlyingError: error)
}
internal func error(_ error: CryptoKitASN1Error) -> CryptoKitMetaError {
    .asn1Error(underlyingError: error)
}
internal func error(_ error: HPKE.Errors) -> CryptoKitMetaError {
    .hpkeError(underlyingError: error)
}
internal func error(_ error: KEM.Errors) -> CryptoKitMetaError {
    .kemError(underlyingError: error)
}
internal func error(_ error: RSAPSSSPKIErrors) -> CryptoKitMetaError {
    .rsapssspkiError(underlyingError: RSAPSSSPKIError(error: error))
}
internal func error(_ error: CryptoBoringWrapperError) -> CryptoKitMetaError {
    switch error {
    case .incorrectKeySize:
        return .cryptoKitError(underlyingError: .incorrectKeySize)
    case .incorrectParameterSize:
        return .cryptoKitError(underlyingError: .incorrectParameterSize)
    case .authenticationFailure:
        return .cryptoKitError(underlyingError: .authenticationFailure)
    case .underlyingCoreCryptoError(let errorCode):
        return .cryptoKitError(underlyingError: .underlyingCoreCryptoError(error: errorCode))
    case .wrapFailure:
        return .cryptoKitError(underlyingError: .wrapFailure)
    case .unwrapFailure:
        return .cryptoKitError(underlyingError: .unwrapFailure)
    case .invalidParameter:
        return .cryptoKitError(underlyingError: .invalidParameter)
    }
}

internal func withCryptoKitMetaError<T>(
    _ body: () throws(CryptoKitMetaError) -> T
) throws(CryptoKitMetaError) -> T {
    try body()
}

internal func withCryptoKitMetaError<T>(
    _ body: () throws(CryptoKitError) -> T
) throws(CryptoKitMetaError) -> T {
    try withCryptoKitError(body)
}

internal func withCryptoKitMetaError<T>(
    _ body: () throws(CryptoBoringWrapperError) -> T
) throws(CryptoKitMetaError) -> T {
    try withCryptoBoringWrapperError(body)
}

internal func withCryptoKitError<T>(
    _ body: () throws(CryptoKitError) -> T
) throws(CryptoKitMetaError) -> T {
    do {
        return try body()
    } catch let cryptoKitError {
        throw error(cryptoKitError)
    }
}

internal func withCryptoBoringWrapperError<T>(
    _ body: () throws(CryptoBoringWrapperError) -> T
) throws(CryptoKitMetaError) -> T {
    do {
        return try body()
    } catch let wrapperError {
        throw error(wrapperError)
    }
}
#else
public typealias CryptoKitMetaError = any Error
@usableFromInline
internal func error(_ error: CryptoKitError) -> CryptoKitError { error }
internal func error(_ error: CryptoKitASN1Error) -> CryptoKitASN1Error { error }
internal func error(_ error: HPKE.Errors) -> HPKE.Errors { error }
internal func error(_ error: KEM.Errors) -> KEM.Errors { error }
internal func error(_ error: RSAPSSSPKIErrors) -> RSAPSSSPKIErrors { error }
internal func error(_ error: CryptoBoringWrapperError) -> CryptoBoringWrapperError { error }
internal func withCryptoKitMetaError<T>(_ body: () throws -> T) throws -> T {
    try body()
}

internal func withCryptoKitError<T>(
    _ body: () throws(CryptoKitError) -> T
) throws -> T {
    try body()
}

internal func withCryptoBoringWrapperError<T>(
    _ body: () throws(CryptoBoringWrapperError) -> T
) throws -> T {
    try body()
}
#endif

#endif
