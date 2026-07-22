#if !hasFeature(Embedded)
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

/// A failure produced by the ARC(P-256) public API.
public enum ARCError: Error, Equatable, Sendable {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidCredentialRequest
    case invalidCredentialResponse
    case invalidCredential
    case invalidPresentation
    case invalidProof
    case invalidPresentationLimit
    case presentationLimitExceeded
    case insufficientOutputCapacity
    case internalFailure
}

internal func withARCError<Result>(
    fallback: ARCError,
    _ operation: () throws -> Result
) throws(ARCError) -> Result {
    do {
        return try operation()
    } catch {
        throw arcError(from: error, fallback: fallback)
    }
}

private func arcError(
    from error: any Error,
    fallback: ARCError
) -> ARCError {
    if let publicError = error as? ARCError {
        return publicError
    }
    if let arcError = error as? ARC.Errors {
        switch arcError {
        case .invalidProof:
            return .invalidProof
        case .invalidPresentationLimit:
            return .invalidPresentationLimit
        case .presentationLimitExceeded:
            return .presentationLimitExceeded
        case .insufficientOutputCapacity:
            return .insufficientOutputCapacity
        case .incorrectRequestDataSize,
            .incorrectResponseDataSize,
            .incorrectCredentialDataSize,
            .incorrectPresentationDataSize,
            .incorrectProofDataSize,
            .incorrectServerCommitmentsSize,
            .incorrectPrivateKeyDataSize,
            .incorrectPublicKeyDataSize,
            .invalidEncoding:
            return fallback
        case .internalFailure:
            return .internalFailure
        }
    }
    if let cryptoKitError = error as? CryptoKitError {
        switch cryptoKitError {
        case .authenticationFailure:
            return .invalidProof
        case .incorrectKeySize, .incorrectParameterSize, .invalidParameter:
            return fallback
        case .underlyingCoreCryptoError, .wrapFailure, .unwrapFailure:
            return .internalFailure
        @unknown default:
            return .internalFailure
        }
    }
    if let oprfError = error as? OPRF.Errors {
        switch oprfError {
        case .invalidProof:
            return .invalidProof
        case .invalidModeForInfo, .incompatibleMode, .missingInfo, .emptyBatch,
            .invalidBatchSize, .invalidScalar, .invalidSeed, .messageTooLong,
            .infoTooLong, .batchTooLarge, .transcriptElementTooLong,
            .keyDerivationFailed:
            return fallback
        }
    }
    if error is ZKPErrors {
        return fallback
    }
    return .internalFailure
}

#endif  // !hasFeature(Embedded)
