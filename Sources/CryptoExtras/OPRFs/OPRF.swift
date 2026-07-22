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

/// (Verifiable Partly-)Oblivious Pseudorandom Functions from RFC 9497.
/// https://www.rfc-editor.org/rfc/rfc9497.html
enum OPRF {}

extension OPRF {
    private static let finalizeLabel = Data("Finalize".utf8)
    private static let infoLabel = Data("Info".utf8)

    enum Errors: Error, Equatable, Sendable {
        case invalidProof
        case invalidModeForInfo
        case incompatibleMode
        case missingInfo
        case emptyBatch
        case invalidBatchSize
        case invalidScalar
        case invalidSeed
        case messageTooLong
        case infoTooLong
        case batchTooLarge
        case transcriptElementTooLong
        case keyDerivationFailed
    }

    struct PreparedFinalizeTranscript<H: HashFunction>: Sendable {
        fileprivate var hasher: H

        fileprivate init(hasher: H) {
            self.hasher = hasher
        }
    }
}

internal func cryptoExtrasError(_ error: OPRF.Errors) -> CryptoKitMetaError {
    #if hasFeature(Embedded)
    switch error {
    case .invalidProof:
        return cryptoExtrasError(CryptoKitError.authenticationFailure)
    case .invalidModeForInfo, .incompatibleMode, .missingInfo, .emptyBatch,
        .invalidBatchSize, .invalidScalar, .invalidSeed, .messageTooLong, .infoTooLong, .batchTooLarge,
        .transcriptElementTooLong, .keyDerivationFailed:
        return cryptoExtrasError(CryptoKitError.incorrectParameterSize)
    }
    #else
    return error
    #endif
}

/// Defines the IETF Serializations for OPRFs
protocol OPRFGroupElement: GroupElement {
    static var oprfRepresentationByteCount: Int { get }
    init(
        oprfRepresentation: UnsafeRawBufferPointer
    ) throws(CryptoKitMetaError)
    var oprfRepresentation: Data { get }
    func writeOPRFRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError)
}

extension OPRFGroupElement {
    init<Bytes: Crypto.ContiguousBytes>(
        oprfRepresentation bytes: Bytes
    ) throws(CryptoKitMetaError) {
        self = try Crypto.withUnsafeBytes(of: bytes) {
            (buffer: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
            try Self(oprfRepresentation: buffer)
        }
    }
}

extension OPRF {
    /// OPRF Modes
    enum Mode: Int, CaseIterable, Sendable {
        // Base mode corresponds to an OPRF
        case base = 0
        // Verifiable mode corresponds to a V(erifiable)OPRF
        case verifiable = 1
        // Partially-Oblivious verifiable OPRF
        case partiallyOblivious = 2
    }
    
    /// IETF Ciphersuites defined for OPRFs
    struct Ciphersuite<H2G: HashToGroup>: Sendable {
        let identifier: String

        init() {
            self.identifier = H2G.oprfCiphersuiteIdentifier
        }
    }

    internal static func protocolContext<H2G: HashToGroup>(mode: Mode, ciphersuite: Ciphersuite<H2G>) -> Data {
        let version = Data("OPRFV1-".utf8)
        let identifier = Data("-\(ciphersuite.identifier)".utf8)
        var context = Data(capacity: version.count + 1 + identifier.count)
        context.append(version)
        context.append(UInt8(mode.rawValue))
        context.append(identifier)
        return context
    }

    internal static func update<H: HashFunction>(
        _ hasher: inout H,
        withByte byte: UInt8
    ) {
        var byte = byte
        withUnsafeBytes(of: &byte) { bytes in
            hasher.update(bufferPointer: bytes)
        }
    }

    internal static func update<H: HashFunction>(
        _ hasher: inout H,
        withTwoByteInteger value: Int
    ) throws(CryptoKitMetaError) {
        guard value >= 0, value <= Int(UInt16.max) else {
            throw cryptoExtrasError(OPRF.Errors.transcriptElementTooLong)
        }
        update(
            &hasher,
            withByte: UInt8(truncatingIfNeeded: value >> 8)
        )
        update(&hasher, withByte: UInt8(truncatingIfNeeded: value))
    }

    internal static func update<H: HashFunction, Bytes: DataProtocol>(
        _ hasher: inout H,
        withTwoByteLengthPrefixed bytes: Bytes
    ) throws(CryptoKitMetaError) {
        try update(&hasher, withTwoByteInteger: bytes.count)
        hasher.update(data: bytes)
    }

    internal static func hashInfoToScalar<
        H2G: HashToGroup,
        Info: DataProtocol
    >(
        _ info: Info,
        domainSeparationTag: Data,
        using hashToGroup: H2G.Type
    ) throws(CryptoKitMetaError) -> H2G.G.Scalar {
        guard info.count <= Int(UInt16.max) else {
            throw cryptoExtrasError(OPRF.Errors.infoTooLong)
        }
        return try H2G.hashToScalar(
            domainSeparationTag: domainSeparationTag
        ) { (hasher: inout H2G.H) throws(CryptoKitMetaError) in
            hasher.update(data: infoLabel)
            try update(
                &hasher,
                withTwoByteLengthPrefixed: info
            )
        }
    }

    internal static func deriveKeyPair<
        H2G: HashToGroup,
        Seed: DataProtocol,
        Info: DataProtocol
    >(
        seed: Seed,
        info: Info,
        mode: Mode,
        ciphersuite: Ciphersuite<H2G>
    ) throws(CryptoKitMetaError) -> (privateKey: H2G.G.Scalar, publicKey: H2G.G.Element) {
        guard seed.count == 32 else {
            throw cryptoExtrasError(OPRF.Errors.invalidSeed)
        }
        guard info.count <= Int(UInt16.max) else {
            throw cryptoExtrasError(OPRF.Errors.infoTooLong)
        }

        let context = protocolContext(mode: mode, ciphersuite: ciphersuite)
        let domainPrefix = Data("DeriveKeyPair".utf8)
        var domainSeparationTag = Data(capacity: domainPrefix.count + context.count)
        domainSeparationTag.append(domainPrefix)
        domainSeparationTag.append(context)

        for counter in UInt8.min...UInt8.max {
            let privateKey = try H2G.hashToScalar(
                domainSeparationTag: domainSeparationTag
            ) { (hasher: inout H2G.H) throws(CryptoKitMetaError) in
                hasher.update(data: seed)
                try update(
                    &hasher,
                    withTwoByteLengthPrefixed: info
                )
                update(&hasher, withByte: counter)
            }
            if privateKey != .zero {
                return (
                    privateKey: privateKey,
                    publicKey: try H2G.G.Element.generator().multiplied(by: privateKey)
                )
            }
        }
        throw cryptoExtrasError(OPRF.Errors.keyDerivationFailed)
    }

    internal static func hashFinalizeTranscript<
        H: HashFunction,
        Element: OPRFGroupElement,
        Message: DataProtocol
    >(
        message: Message,
        info: Data?,
        unblindedElement: Element,
        mode: Mode,
        using hashFunction: H.Type
    ) throws(CryptoKitMetaError) -> H.Digest {
        let preparedTranscript = try prepareFinalizeTranscript(
            message: message,
            using: hashFunction
        )
        return try hashFinalizeTranscript(
            preparedTranscript: preparedTranscript,
            info: info,
            unblindedElement: unblindedElement,
            mode: mode
        )
    }

    internal static func prepareFinalizeTranscript<
        H: HashFunction,
        Message: DataProtocol
    >(
        message: Message,
        using hashFunction: H.Type
    ) throws(CryptoKitMetaError) -> PreparedFinalizeTranscript<H> {
        guard message.count <= Int(UInt16.max) else {
            throw cryptoExtrasError(OPRF.Errors.messageTooLong)
        }
        var hasher = H()
        try update(&hasher, withTwoByteLengthPrefixed: message)
        return PreparedFinalizeTranscript(hasher: hasher)
    }

    internal static func hashFinalizeTranscript<
        H: HashFunction,
        Element: OPRFGroupElement
    >(
        preparedTranscript: PreparedFinalizeTranscript<H>,
        info: Data?,
        unblindedElement: Element,
        mode: Mode
    ) throws(CryptoKitMetaError) -> H.Digest {
        if mode == .partiallyOblivious {
            guard let info else {
                throw cryptoExtrasError(OPRF.Errors.missingInfo)
            }
            guard info.count <= Int(UInt16.max) else {
                throw cryptoExtrasError(OPRF.Errors.infoTooLong)
            }
        }

        var hasher = preparedTranscript.hasher
        if mode == .partiallyOblivious {
            guard let info else {
                throw cryptoExtrasError(OPRF.Errors.missingInfo)
            }
            try update(&hasher, withTwoByteLengthPrefixed: info)
        }
        try update(
            &hasher,
            withTwoByteInteger: Element.oprfRepresentationByteCount
        )
        try withUnsafeTemporaryAllocation(
            byteCount: Element.oprfRepresentationByteCount,
            alignment: 1
        ) {
            (representation: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try unblindedElement.writeOPRFRepresentation(
                into: representation
            )
            hasher.update(
                bufferPointer: UnsafeRawBufferPointer(representation)
            )
        }
        hasher.update(data: finalizeLabel)
        return hasher.finalize()
    }
}
