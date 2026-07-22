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
    struct Client<H2G: HashToGroup> {
        let mode: Mode
        let ciphersuite: Ciphersuite<H2G>
        let context: Data
        let hashToGroupDomainSeparationTag: Data
        let hashToScalarDomainSeparationTag: Data
        typealias G = H2G.G
        
        init(ciphersuite: Ciphersuite<H2G>) {
            self = Self(mode: .base, ciphersuite: ciphersuite)
        }
        
        internal init(mode: Mode, ciphersuite: Ciphersuite<H2G>) {
            let context = protocolContext(mode: mode, ciphersuite: ciphersuite)
            self.mode = mode
            self.ciphersuite = ciphersuite
            self.context = context
            self.hashToGroupDomainSeparationTag = H2G.hashToGroupDomainSeparationTag(
                context: context
            )
            self.hashToScalarDomainSeparationTag = H2G.hashToScalarDomainSeparationTag(
                context: context
            )
        }
        
        func blindMessage(
            _ message: Data,
            blind: G.Scalar = G.Scalar.random
        ) throws(CryptoKitMetaError) -> (blind: G.Scalar, blindedElement: G.Element) {
            guard message.count <= Int(UInt16.max) else {
                throw cryptoExtrasError(OPRF.Errors.messageTooLong)
            }
            guard blind != .zero else {
                throw cryptoExtrasError(OPRF.Errors.invalidScalar)
            }
            let inputElement: G.Element = H2G.hashToGroup(
                message,
                domainSeparationString: hashToGroupDomainSeparationTag
            )
            let blindedElement = blind * inputElement
            return (blind: blind, blindedElement: blindedElement)
        }
        
        func unblind(
            blind: G.Scalar,
            evaluatedElement: G.Element
        ) throws(CryptoKitMetaError) -> G.Element {
            guard blind != .zero else {
                throw cryptoExtrasError(OPRF.Errors.invalidScalar)
            }
            return try blind.inverted() * evaluatedElement
        }
        
        func finalize(message: Data, info: Data?, blind: G.Scalar, evaluatedElement: G.Element) throws(CryptoKitMetaError) -> Data {
            if mode != .partiallyOblivious, info != nil {
                throw cryptoExtrasError(OPRF.Errors.invalidModeForInfo)
            }
            let unblinded = try unblind(
                blind: blind,
                evaluatedElement: evaluatedElement
            )
            
            let digest = try hashFinalizeTranscript(
                message: message,
                info: info,
                unblindedElement: unblinded,
                mode: mode,
                using: H2G.H.self
            )
            return Data(digest)
        }
        
    }
}
