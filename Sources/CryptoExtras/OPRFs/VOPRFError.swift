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
import Crypto

/// A failure produced by the VOPRF(P-384, SHA-384) public API.
public enum VOPRFError: Error, Equatable, Sendable {
    case invalidPublicKey
    case invalidPrivateKey
    case invalidElement
    case invalidProof
    case invalidEncoding
    case invalidScalar
    case invalidSeed
    case messageTooLong
    case keyInfoTooLong
    case keyDerivationFailed
    case internalFailure
}

internal func withVOPRFError<Result>(
    fallback: VOPRFError,
    _ operation: () throws(CryptoKitMetaError) -> Result
) throws(VOPRFError) -> Result {
    do {
        return try operation()
    } catch {
        throw voprfError(from: error, fallback: fallback)
    }
}

private func voprfError(
    from error: CryptoKitMetaError,
    fallback: VOPRFError
) -> VOPRFError {
    #if hasFeature(Embedded)
    switch error {
    case .cryptoKitError(let underlyingError):
        if underlyingError == .authenticationFailure {
            return .invalidProof
        }
        return fallback
    case .asn1Error, .hpkeError, .kemError, .rsapssspkiError:
        return fallback
    @unknown default:
        return fallback
    }
    #else
    if let oprfError = error as? OPRF.Errors {
        switch oprfError {
        case .invalidProof:
            return .invalidProof
        case .invalidScalar:
            return .invalidScalar
        case .invalidSeed:
            return .invalidSeed
        case .messageTooLong:
            return .messageTooLong
        case .infoTooLong:
            return .keyInfoTooLong
        case .keyDerivationFailed:
            return .keyDerivationFailed
        case .invalidModeForInfo, .incompatibleMode, .missingInfo, .emptyBatch,
            .invalidBatchSize, .batchTooLarge, .transcriptElementTooLong:
            return fallback
        }
    }
    if let cryptoKitError = error as? CryptoKitError,
        cryptoKitError == .authenticationFailure
    {
        return .invalidProof
    }
    return fallback
    #endif
}
