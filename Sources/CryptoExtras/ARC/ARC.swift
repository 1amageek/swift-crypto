#if !hasFeature(Embedded)
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
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

/// Anonymous Rate-Limited Credentials (ARC) using the CMZ14 MACGGM construction, as defined in
/// https://chris-wood.github.io/draft-arc/draft-yun-cfrg-arc.html
enum ARC {}

extension ARC {
    enum Errors: Error, Equatable, Sendable {
        case invalidProof
        case invalidPresentationLimit
        case presentationLimitExceeded
        case incorrectRequestDataSize
        case incorrectResponseDataSize
        case incorrectCredentialDataSize
        case incorrectPresentationDataSize
        case incorrectProofDataSize
        case incorrectServerCommitmentsSize
        case incorrectPrivateKeyDataSize
        case incorrectPublicKeyDataSize
        case insufficientOutputCapacity
        case invalidEncoding
        case internalFailure
    }

    /// Ciphersuites for Anonymous Rate-Limited Credentials (ARC)
    struct Ciphersuite<H2G: HashToGroup> {
        let suiteID: Int
        let domain: String

        private init(
            suiteID: Int,
            domain: String
        ) {
            self.suiteID = suiteID
            self.domain = domain
        }

        var scalarByteCount: Int { H2G.G.Scalar.rawRepresentationByteCount }
        var pointByteCount: Int { H2G.G.Element.oprfRepresentationByteCount }
    }

    static func deriveGenerators<H2G: HashToGroup>(for suite: Ciphersuite<H2G>) throws(CryptoKitMetaError) -> (
        generatorG: H2G.G.Element, generatorH: H2G.G.Element
    ) {
        let generatorG = try H2G.G.Element.generator()
        let representationByteCount = H2G.G.Element.oprfRepresentationByteCount
        guard
            representationByteCount > 0,
            representationByteCount <= Int(UInt16.max)
        else {
            throw cryptoExtrasError(OPRF.Errors.transcriptElementTooLong)
        }
        let generatorH = try withUnsafeTemporaryAllocation(
            byteCount: representationByteCount,
            alignment: 1
        ) {
            (representation: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try generatorG.writeOPRFRepresentation(into: representation)
            return try H2G.hashToGroup(
                UnsafeRawBufferPointer(representation),
                domainSeparationString: Data(
                    ("HashToGroup-" + suite.domain + "generatorH").utf8
                )
            )
        }
        return (generatorG, generatorH)
    }
}

extension ARC.Ciphersuite where H2G == CurveHashToGroup<P256> {
    static let arcV1 = Self(
        suiteID: 3,
        domain: "ARCV1-P256"
    )
}

#endif  // !hasFeature(Embedded)
