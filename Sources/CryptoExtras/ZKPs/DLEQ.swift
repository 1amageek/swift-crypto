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

private let dleqSeedLabel = Data("Seed-".utf8)
private let dleqCompositeLabel = Data("Composite".utf8)
private let dleqChallengeLabel = Data("Challenge".utf8)

/// A DLEQ proof as described in RFC 9497.
/// https://www.rfc-editor.org/rfc/rfc9497.html#name-generateproof
struct DLEQProof<GS: GroupScalar> {
    var challenge: GS
    var response: GS

    internal init(challenge: GS, response: GS) {
        self.challenge = challenge
        self.response = response
    }
}

// Discrete Log Equivalence Proof
// Proves that for a value kept secret k, the relation between B=k*A and D=k*C is such that log_A(B)==log_C(D)
struct DLEQ<H2G: HashToGroup> {
    typealias GE = H2G.G.Element

    private static func update<H: HashFunction>(
        _ hasher: inout H,
        withTwoByteLengthPrefixed element: GE
    ) throws(CryptoKitMetaError) {
        try OPRF.update(
            &hasher,
            withTwoByteInteger: GE.oprfRepresentationByteCount
        )
        try withUnsafeTemporaryAllocation(
            byteCount: GE.oprfRepresentationByteCount,
            alignment: 1
        ) {
            (representation: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try element.writeOPRFRepresentation(into: representation)
            hasher.update(
                bufferPointer: UnsafeRawBufferPointer(representation)
            )
        }
    }

    static func composites<Inputs: Collection, Outputs: Collection>(
        secretScalar: GE.Scalar? = nil,
        publicKey: GE,
        context: Data,
        hashToScalarDomainSeparationTag: Data,
        inputs: Inputs,
        outputs: Outputs
    ) throws(CryptoKitMetaError) -> (input: GE, output: GE)
    where Inputs.Element == GE, Outputs.Element == GE {
        guard !inputs.isEmpty else {
            throw cryptoExtrasError(OPRF.Errors.emptyBatch)
        }
        guard inputs.count == outputs.count else {
            throw cryptoExtrasError(OPRF.Errors.invalidBatchSize)
        }
        guard inputs.count <= Int(UInt16.max) + 1 else {
            throw cryptoExtrasError(OPRF.Errors.batchTooLarge)
        }
        guard !publicKey.isIdentity else {
            throw cryptoExtrasError(OPRF.Errors.invalidProof)
        }

        var seedHasher = H2G.H()
        try update(&seedHasher, withTwoByteLengthPrefixed: publicKey)
        try OPRF.update(
            &seedHasher,
            withTwoByteInteger: dleqSeedLabel.count + context.count
        )
        seedHasher.update(data: dleqSeedLabel)
        seedHasher.update(data: context)
        let seed = seedHasher.finalize()
        var inputComposite: GE?
        var outputComposite: GE?
        for (index, pair) in zip(inputs, outputs).enumerated() {
            guard !pair.0.isIdentity, !pair.1.isIdentity else {
                throw cryptoExtrasError(OPRF.Errors.invalidProof)
            }
            let coefficient = try H2G.hashToScalar(
                domainSeparationTag: hashToScalarDomainSeparationTag
            ) { (hasher: inout H2G.H) throws(CryptoKitMetaError) in
                try OPRF.update(
                    &hasher,
                    withTwoByteInteger: H2G.H.Digest.byteCount
                )
                seed.withUnsafeBytes { bytes in
                    hasher.update(bufferPointer: bytes)
                }
                try OPRF.update(&hasher, withTwoByteInteger: index)
                try update(&hasher, withTwoByteLengthPrefixed: pair.0)
                try update(&hasher, withTwoByteLengthPrefixed: pair.1)
                hasher.update(data: dleqCompositeLabel)
            }
            let weightedInput = coefficient * pair.0
            inputComposite = inputComposite.map { weightedInput + $0 } ?? weightedInput
            if secretScalar == nil {
                let weightedOutput = coefficient * pair.1
                outputComposite = outputComposite.map { weightedOutput + $0 } ?? weightedOutput
            }
        }

        guard let inputComposite else {
            throw cryptoExtrasError(OPRF.Errors.emptyBatch)
        }
        guard !inputComposite.isIdentity else {
            throw cryptoExtrasError(OPRF.Errors.invalidProof)
        }
        if let secretScalar {
            let outputComposite = secretScalar * inputComposite
            guard !outputComposite.isIdentity else {
                throw cryptoExtrasError(OPRF.Errors.invalidProof)
            }
            return (input: inputComposite, output: outputComposite)
        }
        guard let outputComposite else {
            throw cryptoExtrasError(OPRF.Errors.emptyBatch)
        }
        guard !outputComposite.isIdentity else {
            throw cryptoExtrasError(OPRF.Errors.invalidProof)
        }
        return (input: inputComposite, output: outputComposite)
    }

    static func challenge(
        context: Data,
        hashToScalarDomainSeparationTag: Data,
        publicKey: GE,
        inputComposite: GE,
        outputComposite: GE,
        generatorCommitment: GE,
        compositeCommitment: GE
    ) throws(CryptoKitMetaError) -> GE.Scalar {
        guard
            !publicKey.isIdentity,
            !inputComposite.isIdentity,
            !outputComposite.isIdentity,
            !generatorCommitment.isIdentity,
            !compositeCommitment.isIdentity
        else {
            throw cryptoExtrasError(OPRF.Errors.invalidProof)
        }
        return try H2G.hashToScalar(
            domainSeparationTag: hashToScalarDomainSeparationTag
        ) { (hasher: inout H2G.H) throws(CryptoKitMetaError) in
            try update(&hasher, withTwoByteLengthPrefixed: publicKey)
            try update(&hasher, withTwoByteLengthPrefixed: inputComposite)
            try update(&hasher, withTwoByteLengthPrefixed: outputComposite)
            try update(&hasher, withTwoByteLengthPrefixed: generatorCommitment)
            try update(&hasher, withTwoByteLengthPrefixed: compositeCommitment)
            hasher.update(data: dleqChallengeLabel)
        }
    }

    static func prove<Inputs: Collection, Outputs: Collection>(
        secretScalar: GE.Scalar,
        generator: GE,
        publicKey: GE,
        inputs: Inputs,
        outputs: Outputs,
        context: Data,
        hashToScalarDomainSeparationTag: Data,
        proofScalar: GE.Scalar
    ) throws(CryptoKitMetaError) -> DLEQProof<GE.Scalar>
    where Inputs.Element == GE, Outputs.Element == GE {
        guard secretScalar != .zero, proofScalar != .zero else {
            throw cryptoExtrasError(OPRF.Errors.invalidScalar)
        }
        let composites = try composites(
            secretScalar: secretScalar,
            publicKey: publicKey,
            context: context,
            hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
            inputs: inputs,
            outputs: outputs
        )
        let generatorCommitment = proofScalar * generator
        let compositeCommitment = proofScalar * composites.input
        let challenge = try challenge(
            context: context,
            hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
            publicKey: publicKey,
            inputComposite: composites.input,
            outputComposite: composites.output,
            generatorCommitment: generatorCommitment,
            compositeCommitment: compositeCommitment
        )
        let response = proofScalar - challenge * secretScalar
        return DLEQProof(challenge: challenge, response: response)
    }

    static func verify<Inputs: Collection, Outputs: Collection>(
        generator: GE,
        publicKey: GE,
        inputs: Inputs,
        outputs: Outputs,
        proof: DLEQProof<GE.Scalar>,
        context: Data,
        hashToScalarDomainSeparationTag: Data
    ) throws(CryptoKitMetaError) -> Bool
    where Inputs.Element == GE, Outputs.Element == GE {
        let composites = try composites(
            publicKey: publicKey,
            context: context,
            hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
            inputs: inputs,
            outputs: outputs
        )
        let generatorCommitment = (proof.response * generator) + (proof.challenge * publicKey)
        let compositeCommitment =
            (proof.response * composites.input) + (proof.challenge * composites.output)
        let challenge = try challenge(
            context: context,
            hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
            publicKey: publicKey,
            inputComposite: composites.input,
            outputComposite: composites.output,
            generatorCommitment: generatorCommitment,
            compositeCommitment: compositeCommitment
        )
        return challenge == proof.challenge
    }
}
