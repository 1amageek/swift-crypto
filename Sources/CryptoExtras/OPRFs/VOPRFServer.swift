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
    struct VerifiableServer<H2G: HashToGroup>: Sendable {
        typealias G = H2G.G
        let server: OPRF.Server<H2G>
        
        init(
            ciphersuite: Ciphersuite<H2G>,
            mode: OPRF.Mode
        ) throws(CryptoKitMetaError) {
            try self.init(
                ciphersuite: ciphersuite,
                privateKey: G.Scalar.randomNonzero(),
                mode: mode
            )
        }

        init(
            ciphersuite: Ciphersuite<H2G>,
            privateKey: G.Scalar,
            mode: OPRF.Mode
        ) throws(CryptoKitMetaError) {
            if mode != .partiallyOblivious && mode != .verifiable {
                throw cryptoExtrasError(OPRF.Errors.incompatibleMode)
            }
            
            self.server = try .init(mode: mode, ciphersuite: ciphersuite, privateKey: privateKey)
        }
        
        var publicKey: G.Element {
            server.publicKey
        }
        
        func evaluate(
            blindedElement: G.Element,
            info: Data? = nil
        ) throws(CryptoKitMetaError) -> (G.Element, DLEQProof<G.Scalar>) {
            try self.evaluate(
                blindedElement: blindedElement,
                info: info,
                proofScalar: G.Scalar.randomNonzero()
            )
        }

        func evaluate(
            blindedElement: G.Element,
            info: Data? = nil,
            proofScalar: G.Scalar
        ) throws(CryptoKitMetaError) ->
        (G.Element, DLEQProof<H2G.G.Element.Scalar>) {
            if info != nil && self.server.mode == .verifiable {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }
            
            let (evaluatedElement, proof) = try self.server.evaluate(blindedElement: blindedElement,
                                                                     info: info,
                                                                     proofScalar: proofScalar)
            
            guard let proof else {
                throw cryptoExtrasError(OPRF.Errors.invalidProof)
            }
            return (evaluatedElement, proof)
        }

        func evaluate(
            blindedElements: [G.Element],
            info: Data? = nil
        ) throws(CryptoKitMetaError) -> ([G.Element], DLEQProof<G.Scalar>) {
            try self.evaluate(
                blindedElements: blindedElements,
                info: info,
                proofScalar: G.Scalar.randomNonzero()
            )
        }

        func evaluate(
            blindedElements: [G.Element],
            info: Data? = nil,
            proofScalar: G.Scalar
        ) throws(CryptoKitMetaError) -> ([G.Element], DLEQProof<G.Scalar>) {
            if info != nil && self.server.mode == .verifiable {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }

            let (evaluatedElements, proof) = try self.server.evaluate(
                blindedElements: blindedElements,
                info: info,
                proofScalar: proofScalar
            )
            guard let proof else {
                throw cryptoExtrasError(OPRF.Errors.invalidProof)
            }
            return (evaluatedElements, proof)
        }
        
        internal func outputMatchesDirectEvaluation(
            message: Data,
            output: Data,
            info: Data?
        ) throws(CryptoKitMetaError) -> Bool {
            try server.outputMatchesDirectEvaluation(
                message: message,
                output: output,
                info: info
            )
        }
    }
}
