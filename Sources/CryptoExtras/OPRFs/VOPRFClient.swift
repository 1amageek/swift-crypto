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

extension OPRF {
    struct VerifiableClient<H2G: HashToGroup> {
        fileprivate let client: OPRF.Client<H2G>
        typealias G = H2G.G
        
        init(ciphersuite: Ciphersuite<H2G>, mode: OPRF.Mode) throws(CryptoKitMetaError) {
            if mode != .partiallyOblivious && mode != .verifiable {
                throw cryptoExtrasError(OPRF.Errors.incompatibleMode)
            }
            
            self.client = .init(mode: mode, ciphersuite: ciphersuite)
        }
        
        func blindMessage(
            _ message: Data,
            blind: G.Scalar = G.Scalar.random
        ) throws(CryptoKitMetaError) -> (blind: G.Scalar, blindedElement: G.Element) {
            try self.client.blindMessage(message, blind: blind)
        }
        
        func finalize(
            message: Data,
            info: Data?,
            blind: G.Scalar,
            blindedElement: G.Element,
            evaluatedElement: G.Element,
            proof: DLEQProof<G.Scalar>,
            publicKey: G.Element
        ) throws(CryptoKitMetaError) -> Data {
            if info != nil && self.client.mode == .verifiable {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }
            if self.client.mode == .verifiable {
                guard try DLEQ<H2G>.verify(
                    generator: H2G.G.Element.generator,
                    publicKey: publicKey,
                    inputs: CollectionOfOne(blindedElement),
                    outputs: CollectionOfOne(evaluatedElement),
                    proof: proof,
                    context: client.context,
                    hashToScalarDomainSeparationTag: client.hashToScalarDomainSeparationTag
                ) else {
                    throw cryptoExtrasError(OPRF.Errors.invalidProof)
                }

                return try self.client.finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement)
            }
            
            guard let info else {
                throw cryptoExtrasError(OPRF.Errors.missingInfo)
            }
            let infoScalar = try OPRF.hashInfoToScalar(
                info,
                domainSeparationTag: client.hashToScalarDomainSeparationTag,
                using: H2G.self
            )
            let tweakedPublicKey = (infoScalar * G.Element.generator) + publicKey
            guard try DLEQ<H2G>.verify(
                generator: H2G.G.Element.generator,
                publicKey: tweakedPublicKey,
                inputs: CollectionOfOne(evaluatedElement),
                outputs: CollectionOfOne(blindedElement),
                proof: proof,
                context: client.context,
                hashToScalarDomainSeparationTag: client.hashToScalarDomainSeparationTag
            ) else {
                throw cryptoExtrasError(OPRF.Errors.invalidProof)
            }
            
            return try self.client.finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement)
        }

        func finalize(
            messages: [Data],
            info: Data?,
            blinds: [G.Scalar],
            blindedElements: [G.Element],
            evaluatedElements: [G.Element],
            proof: DLEQProof<G.Scalar>,
            publicKey: G.Element
        ) throws(CryptoKitMetaError) -> [Data] {
            guard !messages.isEmpty else {
                throw cryptoExtrasError(OPRF.Errors.emptyBatch)
            }
            guard
                messages.count == blinds.count,
                messages.count == blindedElements.count,
                messages.count == evaluatedElements.count
            else {
                throw cryptoExtrasError(OPRF.Errors.invalidBatchSize)
            }
            if info != nil && self.client.mode == .verifiable {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }

            if self.client.mode == .verifiable {
                guard try DLEQ<H2G>.verify(
                    generator: G.Element.generator,
                    publicKey: publicKey,
                    inputs: blindedElements,
                    outputs: evaluatedElements,
                    proof: proof,
                    context: client.context,
                    hashToScalarDomainSeparationTag: client.hashToScalarDomainSeparationTag
                ) else {
                    throw cryptoExtrasError(OPRF.Errors.invalidProof)
                }
            } else {
                guard let info else {
                    throw cryptoExtrasError(OPRF.Errors.missingInfo)
                }
                let infoScalar = try OPRF.hashInfoToScalar(
                    info,
                    domainSeparationTag: client.hashToScalarDomainSeparationTag,
                    using: H2G.self
                )
                let tweakedPublicKey = (infoScalar * G.Element.generator) + publicKey
                guard try DLEQ<H2G>.verify(
                    generator: G.Element.generator,
                    publicKey: tweakedPublicKey,
                    inputs: evaluatedElements,
                    outputs: blindedElements,
                    proof: proof,
                    context: client.context,
                    hashToScalarDomainSeparationTag: client.hashToScalarDomainSeparationTag
                ) else {
                    throw cryptoExtrasError(OPRF.Errors.invalidProof)
                }
            }

            var outputs: [Data] = []
            outputs.reserveCapacity(messages.count)
            for index in messages.indices {
                outputs.append(
                    try self.client.finalize(
                        message: messages[index],
                        info: info,
                        blind: blinds[index],
                        evaluatedElement: evaluatedElements[index]
                    )
                )
            }
            return outputs
        }
        
    }
}
