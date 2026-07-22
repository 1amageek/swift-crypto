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

extension ARC {
    struct Credential<H2G: HashToGroup> {
        typealias Group = H2G.G
        let m1: Group.Scalar
        let U: Group.Element
        let UPrime: Group.Element
        let X1: Group.Element
        let ciphersuite: Ciphersuite<H2G>
        let generatorG: Group.Element
        let generatorH: Group.Element
        var presentationState: PresentationState

        init(credentialResponse: CredentialResponse<H2G>, credentialRequest: CredentialRequest<H2G>, clientSecrets: ClientSecrets<Group.Scalar>, serverPublicKey: ServerPublicKey<H2G>, ciphersuite: Ciphersuite<H2G>, generatorG: Group.Element, generatorH: Group.Element) throws {
            // Verify credential response proof
            guard
                try credentialResponse.verify(request: credentialRequest, serverPublicKey: serverPublicKey, generatorG: generatorG, generatorH: generatorH, ciphersuite: ciphersuite)
            else {
                throw ARC.Errors.invalidProof
            }

            // Decrypt Enc(U') from the credential response, to get U'
            let r1Commitment = try credentialResponse.X1Aux.multiplied(by: clientSecrets.r1)
            let r2Commitment = try credentialResponse.X2Aux.multiplied(by: clientSecrets.r2)
            let UPrime = try credentialResponse.encUPrime
                .subtracting(credentialResponse.X0Aux)
                .subtracting(r1Commitment)
                .subtracting(r2Commitment)

            self = Self(m1: clientSecrets.m1, U: credentialResponse.U, UPrime: UPrime, X1: serverPublicKey.X1, ciphersuite: ciphersuite, generatorG: generatorG, generatorH: generatorH, presentationState: ARC.PresentationState())
        }

        internal init(m1: Group.Scalar, U: Group.Element, UPrime: Group.Element, X1: Group.Element, ciphersuite: Ciphersuite<H2G>, generatorG: Group.Element, generatorH: Group.Element, presentationState: PresentationState) {
            self.m1 = m1
            self.U = U
            self.UPrime = UPrime
            self.X1 = X1
            self.ciphersuite = ciphersuite
            self.generatorG = generatorG
            self.generatorH = generatorH
            self.presentationState = presentationState
        }

        mutating func makePresentation(
            presentationContext: Data,
            presentationLimit: Int,
            optionalNonce: Int? = nil
        ) throws -> (Presentation<H2G>, Int) {
            try self.makePresentation(
                presentationContext: presentationContext,
                presentationLimit: presentationLimit,
                a: Group.Scalar.randomNonzero(),
                r: Group.Scalar.randomNonzero(),
                z: Group.Scalar.randomNonzero(),
                optionalNonce: optionalNonce
            )
        }

        mutating func makePresentation(
            presentationContext: Data,
            presentationLimit: Int,
            a: Group.Scalar,
            r: Group.Scalar,
            z: Group.Scalar,
            optionalNonce: Int? = nil
        ) throws -> (Presentation<H2G>, Int) {
            var updatedPresentationState = self.presentationState
            let nonce = try updatedPresentationState.update(
                presentationContext: presentationContext,
                presentationLimit: presentationLimit,
                optionalNonce: optionalNonce
            )
            let presentation = try Presentation<H2G>(credential: self, a: a, r: r, z: z, presentationContext: presentationContext, nonce: nonce, generatorG: self.generatorG, generatorH: self.generatorH)
            self.presentationState = updatedPresentationState
            return (presentation, nonce)
        }
    }

    struct PresentationState {
        typealias PresentationContext = Data
        typealias PresentationLimit = Int
        typealias NonceSet = Set<Int>
        var state: [PresentationContext: (PresentationLimit, NonceSet)]

        init() {
            self.state = [PresentationContext: (PresentationLimit, NonceSet)]()
        }

        internal init(state: [PresentationContext: (PresentationLimit, NonceSet)]) {
            self.state = state
        }

        mutating func update(presentationContext: Data, presentationLimit: Int, optionalNonce: Int? = nil) throws -> Int {
            if presentationLimit <= 0 {
                throw ARC.Errors.invalidPresentationLimit
            }
            // If optionalNonce is set, use that nonce (eg for test vectors).
            // Otherwise, generate a random nonce that has not yet been used.
            var nonce: Int
            if let optionalNonce {
                nonce = optionalNonce
            } else {
                nonce = Int.random(in: 0..<presentationLimit)
            }

            // Store the nonce in presentationNonces for that presentationContext.
            if let presentationContextState = self.state[presentationContext] {
                if presentationLimit != presentationContextState.0 {
                    throw ARC.Errors.invalidPresentationLimit
                }
                if presentationContextState.1.count >= presentationLimit {
                    throw ARC.Errors.presentationLimitExceeded
                }

                while presentationContextState.1.contains(nonce) {
                    if optionalNonce == nil {
                        // Randomly generated nonce collides with existing nonce for presentationContext
                        nonce = Int.random(in: 0..<presentationLimit)
                    } else {
                        // optionalNonce collides with existing nonce for presentationContext
                        throw ARC.Errors.presentationLimitExceeded
                    }
                }

                var updatedState = presentationContextState
                updatedState.1.insert(nonce)
                self.state[presentationContext] = updatedState
            } else {
                self.state[presentationContext] = (presentationLimit, [nonce])
            }
            return nonce
        }
    }
}

#endif  // !hasFeature(Embedded)
