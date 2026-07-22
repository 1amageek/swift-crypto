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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
import Crypto

extension ARC.CredentialRequest {
    static var proofScalarCount: Int { 5 }

    static func serializedByteCount() throws -> Int {
        try ARC.RepresentationLayout<H2G>(
            pointCount: 2,
            scalarCount: Self.proofScalarCount
        ).byteCount
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: Self.serializedByteCount()
        )
        try writer.writeElement(self.m1Enc)
        try writer.writeElement(self.m2Enc)
        try self.proof.writeRepresentation(
            to: &writer,
            scalarCount: Self.proofScalarCount
        )
        try writer.finish()
    }

    func serialize() throws -> Data {
        try ARC.RepresentationWriter.representation(
            byteCount: Self.serializedByteCount()
        ) { writer in
            try writer.writeElement(self.m1Enc)
            try writer.writeElement(self.m2Enc)
            try self.proof.writeRepresentation(
                to: &writer,
                scalarCount: Self.proofScalarCount
            )
        }
    }

    static func deserialize<D: DataProtocol>(
        requestData: D
    ) throws -> Self {
        let expectedByteCount = try Self.serializedByteCount()
        guard requestData.count == expectedByteCount else {
            throw ARC.Errors.incorrectRequestDataSize
        }
        return try Crypto.withContiguousBytes(of: requestData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let m1Enc = try reader.readElement(H2G.G.Element.self)
            let m2Enc = try reader.readElement(H2G.G.Element.self)
            let proof = try Proof<H2G>.readRepresentation(
                from: &reader,
                scalarCount: Self.proofScalarCount
            )
            try reader.finish()
            return Self(m1Enc: m1Enc, m2Enc: m2Enc, proof: proof)
        }
    }
}

extension ARC.CredentialResponse {
    static var proofScalarCount: Int { 8 }

    static func serializedByteCount() throws -> Int {
        try ARC.RepresentationLayout<H2G>(
            pointCount: 6,
            scalarCount: Self.proofScalarCount
        ).byteCount
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: Self.serializedByteCount()
        )
        try self.writeRepresentation(to: &writer)
        try writer.finish()
    }

    func serialize() throws -> Data {
        try ARC.RepresentationWriter.representation(
            byteCount: Self.serializedByteCount()
        ) { writer in
            try self.writeRepresentation(to: &writer)
        }
    }

    private func writeRepresentation(
        to writer: inout ARC.RepresentationWriter
    ) throws {
        try writer.writeElement(self.U)
        try writer.writeElement(self.encUPrime)
        try writer.writeElement(self.X0Aux)
        try writer.writeElement(self.X1Aux)
        try writer.writeElement(self.X2Aux)
        try writer.writeElement(self.HAux)
        try self.proof.writeRepresentation(
            to: &writer,
            scalarCount: Self.proofScalarCount
        )
    }

    static func deserialize<D: DataProtocol>(
        responseData: D
    ) throws -> Self {
        let expectedByteCount = try Self.serializedByteCount()
        guard responseData.count == expectedByteCount else {
            throw ARC.Errors.incorrectResponseDataSize
        }
        return try Crypto.withContiguousBytes(of: responseData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let U = try reader.readElement(H2G.G.Element.self)
            let encUPrime = try reader.readElement(H2G.G.Element.self)
            let X0Aux = try reader.readElement(H2G.G.Element.self)
            let X1Aux = try reader.readElement(H2G.G.Element.self)
            let X2Aux = try reader.readElement(H2G.G.Element.self)
            let HAux = try reader.readElement(H2G.G.Element.self)
            let proof = try Proof<H2G>.readRepresentation(
                from: &reader,
                scalarCount: Self.proofScalarCount
            )
            try reader.finish()
            return Self(
                U: U,
                encUPrime: encUPrime,
                X0Aux: X0Aux,
                X1Aux: X1Aux,
                X2Aux: X2Aux,
                HAux: HAux,
                proof: proof
            )
        }
    }
}

extension ARC.Presentation {
    static var proofScalarCount: Int { 5 }

    static func serializedByteCount() throws -> Int {
        try ARC.RepresentationLayout<H2G>(
            pointCount: 4,
            scalarCount: Self.proofScalarCount
        ).byteCount
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: Self.serializedByteCount()
        )
        try self.writeRepresentation(to: &writer)
        try writer.finish()
    }

    func serialize() throws -> Data {
        try ARC.RepresentationWriter.representation(
            byteCount: Self.serializedByteCount()
        ) { writer in
            try self.writeRepresentation(to: &writer)
        }
    }

    private func writeRepresentation(
        to writer: inout ARC.RepresentationWriter
    ) throws {
        try writer.writeElement(self.U)
        try writer.writeElement(self.UPrimeCommit)
        try writer.writeElement(self.m1Commit)
        try writer.writeElement(self.tag)
        try self.proof.writeRepresentation(
            to: &writer,
            scalarCount: Self.proofScalarCount
        )
    }

    static func deserialize<D: DataProtocol>(
        presentationData: D
    ) throws -> Self {
        let expectedByteCount = try Self.serializedByteCount()
        guard presentationData.count == expectedByteCount else {
            throw ARC.Errors.incorrectPresentationDataSize
        }
        return try Crypto.withContiguousBytes(of: presentationData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let U = try reader.readElement(H2G.G.Element.self)
            let UPrimeCommit = try reader.readElement(H2G.G.Element.self)
            let m1Commit = try reader.readElement(H2G.G.Element.self)
            let tag = try reader.readElement(H2G.G.Element.self)
            let proof = try Proof<H2G>.readRepresentation(
                from: &reader,
                scalarCount: Self.proofScalarCount
            )
            try reader.finish()
            return Self(
                U: U,
                UPrimeCommit: UPrimeCommit,
                m1Commit: m1Commit,
                tag: tag,
                proof: proof
            )
        }
    }
}

extension ARC.ServerPublicKey {
    static func serializedByteCount() throws -> Int {
        try ARC.RepresentationLayout<H2G>(
            pointCount: 3,
            scalarCount: 0
        ).byteCount
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: Self.serializedByteCount()
        )
        try writer.writeElement(self.X0)
        try writer.writeElement(self.X1)
        try writer.writeElement(self.X2)
        try writer.finish()
    }

    func serialize() throws -> Data {
        try ARC.RepresentationWriter.representation(
            byteCount: Self.serializedByteCount()
        ) { writer in
            try writer.writeElement(self.X0)
            try writer.writeElement(self.X1)
            try writer.writeElement(self.X2)
        }
    }

    static func deserialize<D: DataProtocol>(
        serverPublicKeyData: D
    ) throws -> Self {
        let expectedByteCount = try Self.serializedByteCount()
        guard serverPublicKeyData.count == expectedByteCount else {
            throw ARC.Errors.incorrectServerCommitmentsSize
        }
        return try Crypto.withContiguousBytes(of: serverPublicKeyData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let X0 = try reader.readElement(H2G.G.Element.self)
            let X1 = try reader.readElement(H2G.G.Element.self)
            let X2 = try reader.readElement(H2G.G.Element.self)
            try reader.finish()
            return Self(X0: X0, X1: X1, X2: X2)
        }
    }
}

extension Proof {
    fileprivate func writeRepresentation(
        to writer: inout ARC.RepresentationWriter,
        scalarCount: Int
    ) throws {
        guard scalarCount > 0, self.responses.count == scalarCount - 1 else {
            throw ARC.Errors.internalFailure
        }
        try writer.writeScalar(self.challenge)
        for response in self.responses {
            try writer.writeScalar(response)
        }
    }

    fileprivate static func readRepresentation(
        from reader: inout ARC.RepresentationReader,
        scalarCount: Int
    ) throws -> Self {
        guard scalarCount > 0 else {
            throw ARC.Errors.invalidEncoding
        }
        let challenge = try reader.readScalar(H2G.G.Scalar.self)
        var responses: [H2G.G.Scalar] = []
        responses.reserveCapacity(scalarCount - 1)
        for _ in 1..<scalarCount {
            responses.append(try reader.readScalar(H2G.G.Scalar.self))
        }
        return Self(challenge: challenge, responses: responses)
    }
}

// This representation is client-side credential persistence and is not an ARC wire message.
extension ARC.Credential {
    private static func fixedRepresentationByteCount() throws -> Int {
        try ARC.RepresentationLayout<H2G>(
            pointCount: 3,
            scalarCount: 1
        ).byteCount
    }

    func serializedByteCount() throws -> Int {
        let fixedByteCount = try Self.fixedRepresentationByteCount()
        let stateByteCount = try self.presentationState.serializedByteCount()
        let totalByteCount = fixedByteCount.addingReportingOverflow(
            stateByteCount
        )
        guard !totalByteCount.overflow else {
            throw ARC.Errors.internalFailure
        }
        return totalByteCount.partialValue
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: self.serializedByteCount()
        )
        try self.writeRepresentation(to: &writer)
        try writer.finish()
    }

    func serialize() throws -> Data {
        return try ARC.RepresentationWriter.representation(
            byteCount: self.serializedByteCount()
        ) { writer in
            try self.writeRepresentation(to: &writer)
        }
    }

    private func writeRepresentation(
        to writer: inout ARC.RepresentationWriter
    ) throws {
        try writer.writeScalar(self.m1)
        try writer.writeElement(self.U)
        try writer.writeElement(self.UPrime)
        try writer.writeElement(self.X1)
        try self.presentationState.writeRepresentation(to: &writer)
    }

    static func deserialize<D: DataProtocol>(
        credentialData: D,
        ciphersuite: ARC.Ciphersuite<H2G>
    ) throws -> Self {
        let fixedByteCount = try Self.fixedRepresentationByteCount()
        let minimumByteCount = fixedByteCount.addingReportingOverflow(
            ARC.PresentationState.minimumRepresentationByteCount
        )
        guard
            !minimumByteCount.overflow,
            credentialData.count >= minimumByteCount.partialValue,
            credentialData.count - fixedByteCount
                <= ARC.PresentationState.maximumRepresentationByteCount
        else {
            throw ARC.Errors.incorrectCredentialDataSize
        }
        return try Crypto.withContiguousBytes(of: credentialData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let m1 = try reader.readScalar(H2G.G.Scalar.self)
            guard m1 != .zero else {
                throw ARC.Errors.invalidEncoding
            }
            let U = try reader.readElement(H2G.G.Element.self)
            let UPrime = try reader.readElement(H2G.G.Element.self)
            let X1 = try reader.readElement(H2G.G.Element.self)
            let presentationState = try ARC.PresentationState.readRepresentation(
                from: &reader
            )
            try reader.finish()
            let generators = try ARC.deriveGenerators(
                for: ciphersuite
            )
            return Self(
                m1: m1,
                U: U,
                UPrime: UPrime,
                X1: X1,
                ciphersuite: ciphersuite,
                generatorG: generators.generatorG,
                generatorH: generators.generatorH,
                presentationState: presentationState
            )
        }
    }
}

// This representation is client-side state and is not an ARC wire message.
extension ARC.PresentationState {
    static var minimumRepresentationByteCount: Int { 8 }
    static var maximumRepresentationByteCount: Int { 1_024 * 1_024 }
    private static var representationIdentifier: UInt32 { 0x4152_4301 }
    private static var maximumEntryCount: Int { 4_096 }
    private static var maximumContextByteCount: Int { Int(UInt16.max) }
    private static var maximumNonceCount: Int {
        Self.maximumRepresentationByteCount / MemoryLayout<UInt32>.size
    }

    func serializedByteCount() throws -> Int {
        guard self.state.count <= Self.maximumEntryCount else {
            throw ARC.Errors.internalFailure
        }
        var byteCount = Self.minimumRepresentationByteCount
        for (context, value) in self.state {
            let (presentationLimit, nonces) = value
            guard
                context.count <= Self.maximumContextByteCount,
                UInt32(exactly: presentationLimit) != nil,
                presentationLimit > 0,
                nonces.count <= presentationLimit,
                nonces.count <= Self.maximumNonceCount,
                nonces.allSatisfy({
                    $0 >= 0
                        && $0 < presentationLimit
                        && UInt32(exactly: $0) != nil
                })
            else {
                throw ARC.Errors.internalFailure
            }

            let nonceBytes = nonces.count.multipliedReportingOverflow(
                by: MemoryLayout<UInt32>.size
            )
            let fixedEntryBytes = 2 + context.count + 4 + 4
            let entryBytes = fixedEntryBytes.addingReportingOverflow(
                nonceBytes.partialValue
            )
            let totalBytes = byteCount.addingReportingOverflow(
                entryBytes.partialValue
            )
            guard
                !nonceBytes.overflow,
                !entryBytes.overflow,
                !totalBytes.overflow,
                totalBytes.partialValue <= Self.maximumRepresentationByteCount
            else {
                throw ARC.Errors.internalFailure
            }
            byteCount = totalBytes.partialValue
        }
        return byteCount
    }

    func writeSerializedRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws {
        var writer = try ARC.RepresentationWriter(
            destination: destination,
            requiredByteCount: self.serializedByteCount()
        )
        try self.writeRepresentation(to: &writer)
        try writer.finish()
    }

    func serialize() throws -> Data {
        try ARC.RepresentationWriter.representation(
            byteCount: self.serializedByteCount()
        ) { writer in
            try self.writeRepresentation(to: &writer)
        }
    }

    fileprivate func writeRepresentation(
        to writer: inout ARC.RepresentationWriter
    ) throws {
        _ = try self.serializedByteCount()
        try writer.writeUInt32(Self.representationIdentifier)
        try writer.writeUInt32(UInt32(self.state.count))
        for context in self.state.keys.sorted(by: { left, right in
            left.lexicographicallyPrecedes(right)
        }) {
            guard let value = self.state[context] else {
                throw ARC.Errors.internalFailure
            }
            try writer.writeUInt16(UInt16(context.count))
            try context.withUnsafeBytes { contextBytes in
                try writer.copyBytes(from: contextBytes)
            }
            try writer.writeUInt32(UInt32(value.0))
            try writer.writeUInt32(UInt32(value.1.count))
            for nonce in value.1.sorted() {
                try writer.writeUInt32(UInt32(nonce))
            }
        }
    }

    static func deserialize<D: DataProtocol>(
        presentationStateData: D
    ) throws -> Self {
        guard
            presentationStateData.count >= Self.minimumRepresentationByteCount,
            presentationStateData.count <= Self.maximumRepresentationByteCount
        else {
            throw ARC.Errors.invalidEncoding
        }
        return try Crypto.withContiguousBytes(of: presentationStateData) { bytes in
            var reader = ARC.RepresentationReader(source: bytes)
            let result = try Self.readRepresentation(from: &reader)
            try reader.finish()
            return result
        }
    }

    fileprivate static func readRepresentation(
        from reader: inout ARC.RepresentationReader
    ) throws -> Self {
        guard try reader.readUInt32() == Self.representationIdentifier else {
            throw ARC.Errors.invalidEncoding
        }
        let entryCountValue = try reader.readUInt32()
        guard
            let entryCount = Int(exactly: entryCountValue),
            entryCount <= Self.maximumEntryCount
        else {
            throw ARC.Errors.invalidEncoding
        }

        var state: [Data: (Int, Set<Int>)] = [:]
        state.reserveCapacity(entryCount)
        var previousContext: Data?
        for _ in 0..<entryCount {
            let contextByteCount = Int(try reader.readUInt16())
            let context = try reader.readData(byteCount: contextByteCount)
            if let previousContext {
                guard previousContext.lexicographicallyPrecedes(context) else {
                    throw ARC.Errors.invalidEncoding
                }
            }
            previousContext = context

            let presentationLimitValue = try reader.readUInt32()
            let nonceCountValue = try reader.readUInt32()
            guard
                let presentationLimit = Int(exactly: presentationLimitValue),
                presentationLimit > 0,
                let nonceCount = Int(exactly: nonceCountValue),
                nonceCount <= presentationLimit,
                nonceCount <= Self.maximumNonceCount
            else {
                throw ARC.Errors.invalidEncoding
            }

            var nonces: Set<Int> = []
            nonces.reserveCapacity(nonceCount)
            var previousNonce: Int?
            for _ in 0..<nonceCount {
                let nonceValue = try reader.readUInt32()
                guard
                    let nonce = Int(exactly: nonceValue),
                    nonce < presentationLimit,
                    previousNonce.map({ $0 < nonce }) ?? true
                else {
                    throw ARC.Errors.invalidEncoding
                }
                nonces.insert(nonce)
                previousNonce = nonce
            }
            state[context] = (presentationLimit, nonces)
        }
        return Self(state: state)
    }
}

#endif  // !hasFeature(Embedded)
