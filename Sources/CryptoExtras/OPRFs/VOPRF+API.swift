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

private func encodedVOPRFRepresentation(
    byteCount: Int,
    _ write: (UnsafeMutableRawBufferPointer) throws(VOPRFError) -> Void
) throws(VOPRFError) -> Data {
    var result = Data(count: byteCount)
    do {
        try result.withUnsafeMutableBytes { destination in
            try write(destination)
        }
    } catch let error as VOPRFError {
        throw error
    } catch {
        throw .internalFailure
    }
    return result
}

private func voprfOutputDestination(
    _ destination: UnsafeMutableRawBufferPointer,
    requiredByteCount: Int
) throws(VOPRFError) -> UnsafeMutableRawBufferPointer {
    guard destination.count >= requiredByteCount else {
        throw .insufficientOutputCapacity
    }
    return UnsafeMutableRawBufferPointer(
        rebasing: destination.prefix(requiredByteCount)
    )
}

// MARK: - P384 + VOPRF (P384-SHA384)
extension P384 {
    /// A mechanism to compute the output of a pseudorandom without the client learning the secret or the server
    /// learning the input using the P384-SHA384 Verifiable Oblivious Pseudorandom Function (VOPRF).
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    /// - Seealso: [RFC 9497: OPRF(P-384, SHA-384)](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprfp-384-sha-384).
    public enum _VOPRF {
        typealias H2G = CurveHashToGroup<P384>
        typealias Ciphersuite = OPRF.Ciphersuite<H2G>
        typealias Client = OPRF.VerifiableClient<H2G>
        typealias Server = OPRF.VerifiableServer<H2G>

        static var ciphersuite: Ciphersuite { Ciphersuite() }

        /// A P-384 public key used to blind inputs and finalize blinded elements.
        public struct PublicKey: Sendable {
            /// The byte count of the RFC 9497 OPRF representation.
            public static var oprfRepresentationByteCount: Int {
                H2G.G.Element.oprfRepresentationByteCount
            }

            fileprivate var backingPoint: H2G.G.Element
            fileprivate var client: Client

            fileprivate init(
                backingPoint: H2G.G.Element
            ) throws(CryptoKitMetaError) {
                self.backingPoint = backingPoint
                self.client = try Client(
                    ciphersuite: P384._VOPRF.ciphersuite,
                    mode: .verifiable
                )
            }

            /// Creates a public key from the RFC 9497 OPRF representation.
            public init<Bytes: DataProtocol>(
                oprfRepresentation: Bytes
            ) throws(VOPRFError) {
                self = try withVOPRFError(fallback: .invalidPublicKey) { () throws(CryptoKitMetaError) in
                    try Crypto.withContiguousBytes(of: oprfRepresentation) {
                        (bytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                        try Self(
                            backingPoint: H2G.G.Element(
                                oprfRepresentation: bytes
                            )
                        )
                    }
                }
            }

            /// Writes the RFC 9497 OPRF representation into caller-owned storage.
            public func writeOPRFRepresentation(
                into destination: UnsafeMutableRawBufferPointer
            ) throws(VOPRFError) {
                let output = try voprfOutputDestination(
                    destination,
                    requiredByteCount: Self.oprfRepresentationByteCount
                )
                try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                    try self.backingPoint.writeOPRFRepresentation(
                        into: output
                    )
                }
            }

            /// Returns the RFC 9497 OPRF representation.
            public func oprfRepresentation() throws(VOPRFError) -> Data {
                try encodedVOPRFRepresentation(
                    byteCount: Self.oprfRepresentationByteCount
                ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                    try self.writeOPRFRepresentation(into: destination)
                }
            }
        }

        /// A P-384 private key used to evaluate blinded inputs.
        public struct PrivateKey: Sendable {
            /// The byte count of the canonical private scalar representation.
            public static var rawRepresentationByteCount: Int {
                P384.orderByteCount
            }

            fileprivate var backingScalar: H2G.G.Scalar
            fileprivate var server: Server
            fileprivate var correspondingPublicKey: P384._VOPRF.PublicKey

            fileprivate init(backingScalar: H2G.G.Scalar) throws(CryptoKitMetaError) {
                let server = try Server(
                    ciphersuite: P384._VOPRF.ciphersuite,
                    privateKey: backingScalar,
                    mode: .verifiable
                )
                self.backingScalar = backingScalar
                self.server = server
                self.correspondingPublicKey = try P384._VOPRF.PublicKey(
                    backingPoint: server.publicKey
                )
            }

            /// Creates a random P-384 private key for VOPRF(P-384, SHA-384).
            public init() throws(VOPRFError) {
                try self.init(randomScalar: H2G.G.Scalar.randomNonzero)
            }

            internal init(
                randomScalar: () throws(CryptoKitMetaError) -> H2G.G.Scalar
            ) throws(VOPRFError) {
                self = try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                    try Self(backingScalar: randomScalar())
                }
            }

            /// Creates a private key from its canonical scalar representation.
            public init<Bytes: DataProtocol>(
                rawRepresentation: Bytes
            ) throws(VOPRFError) {
                self = try withVOPRFError(fallback: .invalidPrivateKey) { () throws(CryptoKitMetaError) in
                    try Crypto.withContiguousBytes(of: rawRepresentation) {
                        (bytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                        try Self(
                            backingScalar: H2G.G.Scalar(
                                canonicalRepresentation: bytes
                            )
                        )
                    }
                }
            }

            /// Deterministically derives a VOPRF(P-384, SHA-384) private key as specified by RFC 9497.
            public init<Seed: DataProtocol, KeyInfo: DataProtocol>(
                seed: Seed,
                keyInfo: KeyInfo
            ) throws(VOPRFError) {
                guard seed.count == 32 else {
                    throw .invalidSeed
                }
                guard keyInfo.count <= Int(UInt16.max) else {
                    throw .keyInfoTooLong
                }
                self = try withVOPRFError(fallback: .keyDerivationFailed) { () throws(CryptoKitMetaError) in
                    let keyPair = try OPRF.deriveKeyPair(
                        seed: seed,
                        info: keyInfo,
                        mode: .verifiable,
                        ciphersuite: P384._VOPRF.ciphersuite
                    )
                    return try Self(backingScalar: keyPair.privateKey)
                }
            }

            /// The corresponding public key.
            public var publicKey: P384._VOPRF.PublicKey {
                self.correspondingPublicKey
            }

            /// Writes the canonical private scalar into caller-owned storage.
            public func writeRawRepresentation(
                into destination: UnsafeMutableRawBufferPointer
            ) throws(VOPRFError) {
                let output = try voprfOutputDestination(
                    destination,
                    requiredByteCount: Self.rawRepresentationByteCount
                )
                try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                    try self.backingScalar.writeRawRepresentation(
                        into: output
                    )
                }
            }

            /// Returns the canonical private scalar representation.
            public func rawRepresentation() throws(VOPRFError) -> Data {
                try encodedVOPRFRepresentation(
                    byteCount: Self.rawRepresentationByteCount
                ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                    try self.writeRawRepresentation(into: destination)
                }
            }
        }
    }
}

extension P384._VOPRF {
    /// A blinding value, used to blind an input.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the blind operation.
    public struct Blind: Sendable {
        fileprivate var backing: H2G.G.Scalar

        fileprivate init(backing: H2G.G.Scalar) {
            self.backing = backing
        }
    }

    /// A blinded element, the result of blinding an input.
    ///
    /// Clients should not create values of this type manually; they are created and returned by the blind operation.
    ///
    /// Servers should reconstruct values of this type from the serialized blinded element bytes sent by the client.
    public struct BlindedElement: Sendable {
        /// The byte count of the RFC 9497 OPRF representation.
        public static var oprfRepresentationByteCount: Int {
            H2G.G.Element.oprfRepresentationByteCount
        }

        fileprivate var backing: H2G.G.Element

        fileprivate init(backing: H2G.G.Element) {
            self.backing = backing
        }

        /// Construct a blinded element from its OPRF representation.
        ///
        /// Clients should not create values of this type manually; they are created and returned by the blind operation.
        ///
        /// Servers should reconstruct values of this type from the serialized blinded element bytes sent by the client.
        public init<D: DataProtocol>(oprfRepresentation: D) throws(VOPRFError) {
            self = try withVOPRFError(fallback: .invalidElement) { () throws(CryptoKitMetaError) in
                try Crypto.withContiguousBytes(of: oprfRepresentation) {
                    (bytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                    try Self(
                        backing: H2G.G.Element(oprfRepresentation: bytes)
                    )
                }
            }
        }

        /// Writes the RFC 9497 OPRF representation into caller-owned storage.
        public func writeOPRFRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(VOPRFError) {
            let output = try voprfOutputDestination(
                destination,
                requiredByteCount: Self.oprfRepresentationByteCount
            )
            try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                try self.backing.writeOPRFRepresentation(into: output)
            }
        }

        /// Returns the RFC 9497 OPRF representation.
        public func oprfRepresentation() throws(VOPRFError) -> Data {
            try encodedVOPRFRepresentation(
                byteCount: Self.oprfRepresentationByteCount
            ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                try self.writeOPRFRepresentation(into: destination)
            }
        }
    }

    /// A blinded element and its blind for unblinding.
    ///
    /// This value retains a prepared finalize transcript rather than the input bytes.
    /// Users cannot create values of this type manually; it is created and returned by the blind operation.
    public struct BlindedInput: Sendable {
        var finalizeTranscript: OPRF.PreparedFinalizeTranscript<H2G.H>
        var blind: Blind

        /// The element representing the blinded input to be sent to the server.
        public private(set) var blindedElement: BlindedElement
    }

    /// An evaluated element, the result of the blind evaluate operation.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the evaluate operation.
    public struct EvaluatedElement: Sendable {
        /// The byte count of the RFC 9497 OPRF representation.
        public static var oprfRepresentationByteCount: Int {
            P384.compressedX962PointByteCount
        }

        fileprivate var backing: H2G.G.Element

        fileprivate init(backing: H2G.G.Element) {
            self.backing = backing
        }

        internal init(
            oprfRepresentation: UnsafeRawBufferPointer
        ) throws(CryptoKitMetaError) {
            self.init(backing: try H2G.G.Element(oprfRepresentation: oprfRepresentation))
        }

        /// Writes the RFC 9497 OPRF representation into caller-owned storage.
        public func writeOPRFRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(VOPRFError) {
            let output = try voprfOutputDestination(
                destination,
                requiredByteCount: Self.oprfRepresentationByteCount
            )
            try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                try self.backing.writeOPRFRepresentation(into: output)
            }
        }

        /// Returns the RFC 9497 OPRF representation.
        public func oprfRepresentation() throws(VOPRFError) -> Data {
            try encodedVOPRFRepresentation(
                byteCount: Self.oprfRepresentationByteCount
            ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                try self.writeOPRFRepresentation(into: destination)
            }
        }
    }

    /// A proof that the evaluated element was computed using the agreed key pair.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the evaluate operation.
    public struct Proof: Sendable {
        /// The byte count of the serialized proof.
        public static var rawRepresentationByteCount: Int {
            P384.orderByteCount * 2
        }
        fileprivate var backing: DLEQProof<H2G.G.Scalar>

        fileprivate init(backing: DLEQProof<H2G.G.Scalar>) {
            self.backing = backing
        }

        internal init(
            rawRepresentation: UnsafeRawBufferPointer
        ) throws(CryptoKitMetaError) {
            guard rawRepresentation.count == Self.rawRepresentationByteCount else {
                throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
            }

            let challengeBytes = UnsafeRawBufferPointer(
                rebasing: rawRepresentation.prefix(P384.orderByteCount)
            )
            let responseBytes = UnsafeRawBufferPointer(
                rebasing: rawRepresentation.suffix(P384.orderByteCount)
            )

            let challenge = try H2G.G.Scalar(canonicalRepresentation: challengeBytes)
            let response = try H2G.G.Scalar(canonicalRepresentation: responseBytes)
            self.init(backing: DLEQProof<H2G.G.Scalar>(challenge: challenge, response: response))
        }

        internal init<Bytes: Crypto.ContiguousBytes>(
            rawRepresentation: Bytes
        ) throws(CryptoKitMetaError) {
            self = try Crypto.withUnsafeBytes(of: rawRepresentation) {
                (bytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                try Self(rawRepresentation: bytes)
            }
        }

        fileprivate func writeCanonicalRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(CryptoKitMetaError) {
            guard destination.count == Self.rawRepresentationByteCount else {
                throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
            }
            let challengeDestination = UnsafeMutableRawBufferPointer(
                rebasing: destination.prefix(P384.orderByteCount)
            )
            let responseDestination = UnsafeMutableRawBufferPointer(
                rebasing: destination.suffix(P384.orderByteCount)
            )
            try self.backing.challenge.writeRawRepresentation(
                into: challengeDestination
            )
            try self.backing.response.writeRawRepresentation(
                into: responseDestination
            )
        }

        /// Writes the serialized proof into caller-owned storage.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(VOPRFError) {
            let output = try voprfOutputDestination(
                destination,
                requiredByteCount: Self.rawRepresentationByteCount
            )
            try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                try self.writeCanonicalRepresentation(into: output)
            }
        }

        /// Returns the serialized proof to send to the client.
        public func rawRepresentation() throws(VOPRFError) -> Data {
            try encodedVOPRFRepresentation(
                byteCount: Self.rawRepresentationByteCount
            ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                try self.writeRawRepresentation(into: destination)
            }
        }
    }

    /// The result of blind evaluation: the evaluated element and corresponding proof.
    ///
    /// Servers should not create values of this type manually; they are created and returned by the evaluate operation.
    ///
    /// Clients should reconstruct values of this type from the serialized blind evaluation bytes sent by the server.
    public struct BlindEvaluation: Sendable {
        /// The byte count of the serialized blind evaluation.
        public static var rawRepresentationByteCount: Int {
            EvaluatedElement.oprfRepresentationByteCount
                + Proof.rawRepresentationByteCount
        }

        /// The evaluated element.
        public private(set) var evaluatedElement: EvaluatedElement

        /// The proof.
        public private(set) var proof: Proof

        fileprivate init(evaluatedElement: EvaluatedElement, proof: Proof) {
            self.evaluatedElement = evaluatedElement
            self.proof = proof
        }

        /// Construct a blind evaluation from its serialized representation.
        ///
        /// Servers should not create values of this type manually; they are created and returned by the evaluate operation.
        ///
        /// Clients should reconstruct values of this type from the serialized blind evaluation bytes sent by the server.
        public init<D: DataProtocol>(rawRepresentation: D) throws(VOPRFError) {
            guard rawRepresentation.count == Self.rawRepresentationByteCount else {
                throw .invalidEncoding
            }
            self = try Crypto.withContiguousBytes(of: rawRepresentation) {
                (bytes: UnsafeRawBufferPointer) throws(VOPRFError) in
                let evaluatedElementBytes = UnsafeRawBufferPointer(
                    rebasing: bytes.prefix(
                        EvaluatedElement.oprfRepresentationByteCount
                    )
                )
                let proofBytes = UnsafeRawBufferPointer(
                    rebasing: bytes.suffix(Proof.rawRepresentationByteCount)
                )
                let evaluatedElement = try withVOPRFError(
                    fallback: .invalidElement
                ) { () throws(CryptoKitMetaError) in
                    try EvaluatedElement(
                        oprfRepresentation: evaluatedElementBytes
                    )
                }
                let proof = try withVOPRFError(
                    fallback: .invalidProof
                ) { () throws(CryptoKitMetaError) in
                    try Proof(rawRepresentation: proofBytes)
                }
                return Self(
                    evaluatedElement: evaluatedElement,
                    proof: proof
                )
            }
        }

        fileprivate func writeComponents(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(CryptoKitMetaError) {
            guard destination.count == Self.rawRepresentationByteCount else {
                throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
            }
            let elementDestination = UnsafeMutableRawBufferPointer(
                rebasing: destination.prefix(EvaluatedElement.oprfRepresentationByteCount)
            )
            let proofDestination = UnsafeMutableRawBufferPointer(
                rebasing: destination.suffix(Proof.rawRepresentationByteCount)
            )
            try self.evaluatedElement.backing.writeOPRFRepresentation(
                into: elementDestination
            )
            try self.proof.writeCanonicalRepresentation(into: proofDestination)
        }

        /// Writes the serialized blind evaluation into caller-owned storage.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(VOPRFError) {
            let output = try voprfOutputDestination(
                destination,
                requiredByteCount: Self.rawRepresentationByteCount
            )
            try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
                try self.writeComponents(into: output)
            }
        }

        /// Returns the serialized blind evaluation to send to the client.
        public func rawRepresentation() throws(VOPRFError) -> Data {
            try encodedVOPRFRepresentation(
                byteCount: Self.rawRepresentationByteCount
            ) { (destination: UnsafeMutableRawBufferPointer) throws(VOPRFError) in
                try self.writeRawRepresentation(into: destination)
            }
        }
    }
}

extension P384._VOPRF.PublicKey {
    internal func blind<Input: DataProtocol>(
        _ input: Input,
        with fixedBlind: P384._VOPRF.H2G.G.Scalar
    ) throws(CryptoKitMetaError) -> P384._VOPRF.BlindedInput {
        guard input.count <= Int(UInt16.max) else {
            throw cryptoExtrasError(OPRF.Errors.messageTooLong)
        }
        let finalizeTranscript = try OPRF.prepareFinalizeTranscript(
            message: input,
            using: P384._VOPRF.H2G.H.self
        )
        return try Crypto.withContiguousBytes(of: input) {
            (inputBytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
            let (blind, blindedElement) = try self.client.blindMessage(
                inputBytes,
                blind: fixedBlind
            )
            return P384._VOPRF.BlindedInput(
                finalizeTranscript: finalizeTranscript,
                blind: P384._VOPRF.Blind(backing: blind),
                blindedElement: P384._VOPRF.BlindedElement(
                    backing: blindedElement
                )
            )
        }
    }

    /// Blind an input to be evaluated by the server using the VOPRF protocol.
    ///
    /// - Parameter input: The input to blind.
    /// - Returns: The blinded input, and its blind for unblinding.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func blind<D: DataProtocol>(_ input: D) throws(VOPRFError) -> P384._VOPRF.BlindedInput {
        try self.blind(
            input,
            randomScalar: P384._VOPRF.H2G.G.Scalar.randomNonzero
        )
    }

    internal func blind<D: DataProtocol>(
        _ input: D,
        randomScalar: () throws(CryptoKitMetaError) -> P384._VOPRF.H2G.G.Scalar
    ) throws(VOPRFError) -> P384._VOPRF.BlindedInput {
        guard input.count <= Int(UInt16.max) else {
            throw .messageTooLong
        }
        return try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
            try self.blind(input, with: randomScalar())
        }
    }

    /// Compute the output of the VOPRF by verifying the server proof, and unblinding and hashing the evaluated element.
    /// 
    /// - Parameter blindedInput: The blinded input from the blind operation, computed earlier by the client.
    /// - Parameter blindEvaluation: The blind evaluation from the evaluate operation, received from the server.
    /// - Returns: The PRF output.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func finalize(
        _ blindedInput: P384._VOPRF.BlindedInput,
        using blindEvaluation: P384._VOPRF.BlindEvaluation
    ) throws(VOPRFError) -> Data {
        try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
            try self.client.finalize(
                preparedTranscript: blindedInput.finalizeTranscript,
                info: nil,
                blind: blindedInput.blind.backing,
                blindedElement: blindedInput.blindedElement.backing,
                evaluatedElement: blindEvaluation.evaluatedElement.backing,
                proof: blindEvaluation.proof.backing,
                publicKey: self.backingPoint
            )
        }
    }
}

extension P384._VOPRF.PrivateKey {
    static let hashToGroupDomainSeparationTag: Data = {
        let context = OPRF.protocolContext(mode: .verifiable, ciphersuite: P384._VOPRF.ciphersuite)
        return P384._VOPRF.H2G.hashToGroupDomainSeparationTag(context: context)
    }()

    internal func evaluate(_ blindedElement: P384._VOPRF.BlindedElement, using fixedProofScalar: P384._VOPRF.H2G.G.Scalar) throws(CryptoKitMetaError) -> P384._VOPRF.BlindEvaluation {
        let (evaluatedElement, proof) = try self.server.evaluate(blindedElement: blindedElement.backing, proofScalar: fixedProofScalar)
        return P384._VOPRF.BlindEvaluation(
            evaluatedElement: P384._VOPRF.EvaluatedElement(backing: evaluatedElement),
            proof: P384._VOPRF.Proof(backing: proof)
        )
    }

    /// Compute the evaluated element and associated proof for verification by the client.
    ///
    /// - Parameter blindedElement: The blinded element from the blind operation, received from the client.
    /// - Returns: The blind evaluation to be sent to the client.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func evaluate(
        _ blindedElement: P384._VOPRF.BlindedElement
    ) throws(VOPRFError) -> P384._VOPRF.BlindEvaluation {
        try self.evaluate(
            blindedElement,
            randomScalar: P384._VOPRF.H2G.G.Scalar.randomNonzero
        )
    }

    internal func evaluate(
        _ blindedElement: P384._VOPRF.BlindedElement,
        randomScalar: () throws(CryptoKitMetaError) -> P384._VOPRF.H2G.G.Scalar
    ) throws(VOPRFError) -> P384._VOPRF.BlindEvaluation {
        try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
            try self.evaluate(blindedElement, using: randomScalar())
        }
    }

    /// Compute the PRF without blinding or proof.
    ///
    /// - Parameter input: The input message for which to compute the PRF.
    /// - Returns: The computed PRF, the same as the VOPRF, without the blinding or proof.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol - Evaluate](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-7).
    public func evaluate<D: DataProtocol>(_ input: D) throws(VOPRFError) -> Data {
        guard input.count <= Int(UInt16.max) else {
            throw .messageTooLong
        }
        return try withVOPRFError(fallback: .internalFailure) { () throws(CryptoKitMetaError) in
            let inputElement = try Crypto.withContiguousBytes(of: input) {
                (inputBytes: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
                try P384._VOPRF.H2G.hashToGroup(
                    inputBytes,
                    domainSeparationString: Self.hashToGroupDomainSeparationTag
                )
            }
            let evaluatedElement = try inputElement.multiplied(by: self.backingScalar)
            let digest = try OPRF.hashFinalizeTranscript(
                message: input,
                info: nil,
                unblindedElement: evaluatedElement,
                mode: .verifiable,
                using: P384._VOPRF.H2G.H.self
            )
            return Data(digest)
        }
    }
}
