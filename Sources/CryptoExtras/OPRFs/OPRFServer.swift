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

extension OPRF {
    struct Server<H2G: HashToGroup>: Sendable {
        typealias G = H2G.G
        let mode: Mode
        let ciphersuite: Ciphersuite<H2G>
        let privateKey: G.Scalar
        let publicKey: G.Element
        let context: Data
        let hashToGroupDomainSeparationTag: Data
        let hashToScalarDomainSeparationTag: Data
        
        init(
            ciphersuite: Ciphersuite<H2G>
        ) throws(CryptoKitMetaError) {
            try self.init(
                mode: .base,
                ciphersuite: ciphersuite,
                privateKey: G.Scalar.randomNonzero()
            )
        }

        init(
            ciphersuite: Ciphersuite<H2G>,
            privateKey: G.Scalar
        ) throws(CryptoKitMetaError) {
            try self.init(mode: .base, ciphersuite: ciphersuite, privateKey: privateKey)
        }

        internal init(
            mode: Mode,
            ciphersuite: Ciphersuite<H2G>
        ) throws(CryptoKitMetaError) {
            try self.init(
                mode: mode,
                ciphersuite: ciphersuite,
                privateKey: G.Scalar.randomNonzero()
            )
        }
        
        internal init(
            mode: Mode,
            ciphersuite: Ciphersuite<H2G>,
            privateKey: G.Scalar
        ) throws(CryptoKitMetaError) {
            guard privateKey != .zero else {
                throw cryptoExtrasError(OPRF.Errors.invalidScalar)
            }
            self.mode = mode
            self.ciphersuite = ciphersuite
            self.privateKey = privateKey
            self.publicKey = try G.Element.generator().multiplied(by: privateKey)
            let context = protocolContext(mode: mode, ciphersuite: ciphersuite)
            self.context = context
            self.hashToGroupDomainSeparationTag = H2G.hashToGroupDomainSeparationTag(
                context: context
            )
            self.hashToScalarDomainSeparationTag = H2G.hashToScalarDomainSeparationTag(
                context: context
            )
        }
        
        func evaluate(
            blindedElement: G.Element,
            info: Data? = nil
        ) throws(CryptoKitMetaError) -> (G.Element, DLEQProof<G.Scalar>?) {
            let proofScalar: G.Scalar =
                self.mode == .base ? .zero : try G.Scalar.randomNonzero()
            return try self.evaluate(
                blindedElement: blindedElement,
                info: info,
                proofScalar: proofScalar
            )
        }

        func evaluate(
            blindedElement: G.Element,
            info: Data? = nil,
            proofScalar: G.Scalar
        ) throws(CryptoKitMetaError) ->
        (G.Element, DLEQProof<H2G.G.Element.Scalar>?) {
            if mode != .partiallyOblivious, info != nil {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }
            if mode == .base || mode == .verifiable {
                let evaluatedElement = try blindedElement.multiplied(by: self.privateKey)
                if mode == .base { return (evaluatedElement, nil) }

                let proof = try DLEQ<H2G>.prove(
                    secretScalar: self.privateKey,
                    generator: G.Element.generator(),
                    publicKey: self.publicKey,
                    inputs: CollectionOfOne(blindedElement),
                    outputs: CollectionOfOne(evaluatedElement),
                    context: context,
                    hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
                    proofScalar: proofScalar
                )
                return (evaluatedElement, proof)
            }

            guard let info else {
                throw cryptoExtrasError(OPRF.Errors.missingInfo)
            }
            let infoScalar = try OPRF.hashInfoToScalar(
                info,
                domainSeparationTag: hashToScalarDomainSeparationTag,
                using: H2G.self
            )
            let tweakedKey = try privateKey.adding(infoScalar)
            guard tweakedKey != .zero else {
                throw cryptoExtrasError(OPRF.Errors.invalidScalar)
            }
            let evaluatedElement = try blindedElement.multiplied(by: tweakedKey.inverted())
            let tweakedPublicKey = try G.Element.generator().multiplied(by: tweakedKey)
            let proof = try DLEQ<H2G>.prove(
                secretScalar: tweakedKey,
                generator: G.Element.generator(),
                publicKey: tweakedPublicKey,
                inputs: CollectionOfOne(evaluatedElement),
                outputs: CollectionOfOne(blindedElement),
                context: context,
                hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
                proofScalar: proofScalar
            )
            return (evaluatedElement, proof)
        }

        func evaluate(
            blindedElements: [G.Element],
            info: Data? = nil
        ) throws(CryptoKitMetaError) -> ([G.Element], DLEQProof<G.Scalar>?) {
            let proofScalar: G.Scalar =
                self.mode == .base ? .zero : try G.Scalar.randomNonzero()
            return try self.evaluate(
                blindedElements: blindedElements,
                info: info,
                proofScalar: proofScalar
            )
        }

        func evaluate(
            blindedElements: [G.Element],
            info: Data? = nil,
            proofScalar: G.Scalar
        ) throws(CryptoKitMetaError) -> ([G.Element], DLEQProof<G.Scalar>?) {
            guard !blindedElements.isEmpty else {
                throw cryptoExtrasError(OPRF.Errors.emptyBatch)
            }
            if mode != .partiallyOblivious, info != nil {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }
            if mode == .base || mode == .verifiable {
                var evaluatedElements: [G.Element] = []
                evaluatedElements.reserveCapacity(blindedElements.count)
                for blindedElement in blindedElements {
                    evaluatedElements.append(
                        try blindedElement.multiplied(by: privateKey)
                    )
                }
                if mode == .base {
                    return (evaluatedElements, nil)
                }

                let proof = try DLEQ<H2G>.prove(
                    secretScalar: privateKey,
                    generator: G.Element.generator(),
                    publicKey: publicKey,
                    inputs: blindedElements,
                    outputs: evaluatedElements,
                    context: context,
                    hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
                    proofScalar: proofScalar
                )
                return (evaluatedElements, proof)
            }

            guard let info else {
                throw cryptoExtrasError(OPRF.Errors.missingInfo)
            }
            let infoScalar = try OPRF.hashInfoToScalar(
                info,
                domainSeparationTag: hashToScalarDomainSeparationTag,
                using: H2G.self
            )
            let tweakedKey = try privateKey.adding(infoScalar)
            guard tweakedKey != .zero else {
                throw cryptoExtrasError(OPRF.Errors.invalidScalar)
            }
            let inverseTweakedKey = try tweakedKey.inverted()
            var evaluatedElements: [G.Element] = []
            evaluatedElements.reserveCapacity(blindedElements.count)
            for blindedElement in blindedElements {
                evaluatedElements.append(
                    try blindedElement.multiplied(by: inverseTweakedKey)
                )
            }
            let tweakedPublicKey = try G.Element.generator().multiplied(by: tweakedKey)
            let proof = try DLEQ<H2G>.prove(
                secretScalar: tweakedKey,
                generator: G.Element.generator(),
                publicKey: tweakedPublicKey,
                inputs: evaluatedElements,
                outputs: blindedElements,
                context: context,
                hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
                proofScalar: proofScalar
            )
            return (evaluatedElements, proof)
        }
        
        internal func outputMatchesDirectEvaluation(
            message: Data,
            output: Data,
            info: Data?
        ) throws(CryptoKitMetaError) -> Bool {
            let inputElement: H2G.G.Element = try H2G.hashToGroup(
                message,
                domainSeparationString: hashToGroupDomainSeparationTag
            )
            let (issuedElement, _) = try evaluate(blindedElement: inputElement, info: info)
            let digest = try hashFinalizeTranscript(
                message: message,
                info: info,
                unblindedElement: issuedElement,
                mode: mode,
                using: H2G.H.self
            )
            return output == Data(digest)
        }
    }
}
