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
    enum Errors: Error {
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
    }

    /// Ciphersuites for Anonymous Rate-Limited Credentials (ARC)
    struct Ciphersuite<H2G: HashToGroup> {
        let suiteID: Int
        let domain: String
        let scalarByteCount: Int
        let pointByteCount: Int

        private init(
            suiteID: Int,
            domain: String,
            scalarByteCount: Int,
            pointByteCount: Int
        ) {
            self.suiteID = suiteID
            self.domain = domain
            self.scalarByteCount = scalarByteCount
            self.pointByteCount = pointByteCount
        }
    }

    static func getGenerators<H2G: HashToGroup>(suite: Ciphersuite<H2G>) -> (
        generatorG: H2G.G.Element, generatorH: H2G.G.Element
    ) {
        let generatorG = H2G.G.Element.generator
        let generatorH = H2G.hashToGroup(generatorG.oprfRepresentation, domainSeparationString: Data(("HashToGroup-" + suite.domain + "generatorH").utf8))
        return (generatorG, generatorH)
    }
}

extension ARC.Ciphersuite where H2G == CurveHashToGroup<P256> {
    static let arcV1 = Self(
        suiteID: 3,
        domain: "ARCV1-P256",
        scalarByteCount: P256.orderByteCount,
        pointByteCount: P256.compressedX962PointByteCount
    )
}

#endif  // !hasFeature(Embedded)
