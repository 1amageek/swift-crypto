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

// MARK: - P256 + ARC(P-256)
extension P256 {
    /// Anonymous Rate-Limited Credentials (ARC).
    ///
    /// A specialization of keyed-verification anonymous credentials with support for rate limiting.
    ///
    /// - Seealso: [IETF Internet Draft: draft-yun-cfrg-arc-00](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc).
    public enum _ARCV1 {
        internal typealias H2G = CurveHashToGroup<P256>
        internal typealias Ciphersuite = ARC.Ciphersuite<H2G>
        fileprivate typealias Server = ARC.Server<H2G>

        internal static let ciphersuite: Ciphersuite = .arcV1
    }
}

extension P256._ARCV1 {
    /// The server secrets used to issue and verify credentials.
    public struct PrivateKey: Sendable {
        /// The byte count of the canonical private-key representation.
        public static var rawRepresentationByteCount: Int {
            4 * P256.orderByteCount
        }

        fileprivate var backing: ARC.Server<H2G>

        /// Creates a random private key for ARC(P-256).
        public init() throws(ARCError) {
            self.backing = try withARCError(fallback: .internalFailure) {
                try ARC.Server(ciphersuite: P256._ARCV1.ciphersuite)
            }
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ns];
        //       uint8 x1[Ns];
        //       uint8 x2[Ns];
        //       uint8 x0Blinding[Ns];
        //     } ServerPrivateKey;
        //
        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidPrivateKey) {
                guard rawRepresentation.count == Self.rawRepresentationByteCount else {
                    throw ARC.Errors.incorrectPrivateKeyDataSize
                }
                let scalars = try Crypto.withContiguousBytes(
                    of: rawRepresentation
                ) { bytes in
                    var reader = ARC.RepresentationReader(source: bytes)
                    let x0 = try reader.readScalar(H2G.G.Scalar.self)
                    let x1 = try reader.readScalar(H2G.G.Scalar.self)
                    let x2 = try reader.readScalar(H2G.G.Scalar.self)
                    let x0Blinding = try reader.readScalar(H2G.G.Scalar.self)
                    try reader.finish()
                    return (x0, x1, x2, x0Blinding)
                }
                guard
                    scalars.0 != .zero,
                    scalars.1 != .zero,
                    scalars.2 != .zero,
                    scalars.3 != .zero
                else {
                    throw ARC.Errors.invalidEncoding
                }
                return try ARC.Server(
                    ciphersuite: P256._ARCV1.ciphersuite,
                    x0: scalars.0,
                    x1: scalars.1,
                    x2: scalars.2,
                    x0Blinding: scalars.3
                )
            }
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ns];
        //       uint8 x1[Ns];
        //       uint8 x2[Ns];
        //       uint8 x0Blinding[Ns];
        //     } ServerPrivateKey;
        //
        /// Writes exactly the required prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                var writer = try ARC.RepresentationWriter(
                    destination: destination,
                    requiredByteCount: Self.rawRepresentationByteCount
                )
                try writer.writeScalar(self.backing.serverPrivateKey.x0)
                try writer.writeScalar(self.backing.serverPrivateKey.x1)
                try writer.writeScalar(self.backing.serverPrivateKey.x2)
                try writer.writeScalar(self.backing.serverPrivateKey.x0Blinding)
                try writer.finish()
            }
        }

        /// Returns the canonical private-key representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try ARC.RepresentationWriter.representation(
                    byteCount: Self.rawRepresentationByteCount
                ) { writer in
                    try writer.writeScalar(self.backing.serverPrivateKey.x0)
                    try writer.writeScalar(self.backing.serverPrivateKey.x1)
                    try writer.writeScalar(self.backing.serverPrivateKey.x2)
                    try writer.writeScalar(self.backing.serverPrivateKey.x0Blinding)
                }
            }
        }

        public var publicKey: P256._ARCV1.PublicKey {
            P256._ARCV1.PublicKey(backing: self.backing.serverPublicKey)
        }
    }

    /// The server public key, used by clients to create anonymous credentials in conjunction with the server.
    public struct PublicKey: Sendable {
        /// The byte count of the ARC public-key representation.
        public static var rawRepresentationByteCount: Int {
            3 * P256.compressedX962PointByteCount
        }

        fileprivate var backing: ARC.ServerPublicKey<H2G>

        fileprivate init(backing: ARC.ServerPublicKey<H2G>) {
            self.backing = backing
        }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidPublicKey) {
                guard rawRepresentation.count == Self.rawRepresentationByteCount else {
                    throw ARC.Errors.incorrectPublicKeyDataSize
                }
                return try ARC.ServerPublicKey.deserialize(
                    serverPublicKeyData: rawRepresentation
                )
            }
        }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        /// Writes exactly the required prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                try self.backing.writeSerializedRepresentation(into: destination)
            }
        }

        /// Returns the ARC public-key representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serialize()
            }
        }
    }

    /// A credential request, created by the client, to be sent to the server.
    ///
    /// Clients should not create values of this type manually; they should use the prepare method on the public key.
    ///
    /// Servers should reconstruct values of this type from the serialized bytes sent by the client.
    public struct CredentialRequest: Sendable {
        /// The byte count of an ARC credential-request representation.
        public static var rawRepresentationByteCount: Int {
            2 * P256.compressedX962PointByteCount + 5 * P256.orderByteCount
        }

        var backing: ARC.CredentialRequest<H2G>

        fileprivate init(backing: ARC.CredentialRequest<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidCredentialRequest) {
                try ARC.CredentialRequest.deserialize(
                    requestData: rawRepresentation
                )
            }
        }

        /// Writes exactly the required prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                try self.backing.writeSerializedRepresentation(into: destination)
            }
        }

        /// Returns the ARC credential-request representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serialize()
            }
        }
    }

    /// A credential request to be sent to the server, and associated client secrets.
    ///
    /// Users cannot create values of this type manually; they are created using the prepare method on the public key.
    public struct Precredential: Sendable {
        /// This backing type binds many things together, including the server commitments, client secrets, credential
        /// request, and presentation limit.
        internal var backing: ARC.Precredential<H2G>

        /// The credential request to be sent to the server.
        public var credentialRequest: CredentialRequest {
            CredentialRequest(backing: self.backing.credentialRequest)
        }
    }

    /// A credential response, created by the server, to be sent to the client.
    ///
    /// Servers should not create values of this type manually; they should use the issue method on the private key.
    ///
    /// Clients should reconstruct values of this type from the serialized bytes sent by the server.
    public struct CredentialResponse: Sendable {
        /// The byte count of an ARC credential-response representation.
        public static var rawRepresentationByteCount: Int {
            6 * P256.compressedX962PointByteCount + 8 * P256.orderByteCount
        }

        var backing: ARC.CredentialResponse<H2G>

        fileprivate init(backing: ARC.CredentialResponse<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidCredentialResponse) {
                try ARC.CredentialResponse.deserialize(
                    responseData: rawRepresentation
                )
            }
        }

        /// Writes exactly the required prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                try self.backing.writeSerializedRepresentation(into: destination)
            }
        }

        /// Returns the ARC credential-response representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serialize()
            }
        }
    }


    /// A credential, created by the client using the response from the server.
    ///
    /// Users cannot create values of this type manually; they are created using the issue method on the public key.
    public struct Credential: Sendable {
        var backing: ARC.Credential<H2G>

        fileprivate init(backing: ARC.Credential<H2G>) {
            self.backing = backing
        }

        /// Restores a credential and its local presentation-limit state.
        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidCredential) {
                try ARC.Credential.deserialize(
                    credentialData: rawRepresentation,
                    ciphersuite: P256._ARCV1.ciphersuite
                )
            }
        }

        /// Returns the byte count required to persist this credential.
        public func rawRepresentationByteCount() throws(ARCError) -> Int {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serializedByteCount()
            }
        }

        /// Writes exactly the required credential prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                try self.backing.writeSerializedRepresentation(
                    into: destination
                )
            }
        }

        /// Returns a representation that persists this credential and its local presentation-limit state.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serialize()
            }
        }
    }

    /// A rate-limit tag carried by an ARC presentation.
    public struct Tag: Sendable {
        /// The byte count of the tag's group-element representation.
        public static var rawRepresentationByteCount: Int {
            P256.compressedX962PointByteCount
        }

        fileprivate var backing: H2G.G.Element

        fileprivate init(backing: H2G.G.Element) {
            self.backing = backing
        }

        /// Writes exactly the required tag prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        /// Writes exactly the required prefix without retaining the destination.
        /// Extra capacity remains unchanged; insufficient capacity fails before writing.
        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                var writer = try ARC.RepresentationWriter(
                    destination: destination,
                    requiredByteCount: Self.rawRepresentationByteCount
                )
                try writer.writeElement(self.backing)
                try writer.finish()
            }
        }

        /// Returns the tag's group-element representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try ARC.RepresentationWriter.representation(
                    byteCount: Self.rawRepresentationByteCount
                ) { writer in
                    try writer.writeElement(self.backing)
                }
            }
        }
    }

    /// A presentation, created by the client from a credential, to be sent to the server to verify.
    ///
    /// Users cannot create values of this type manually; they are created using the present method on the credential.
    public struct Presentation: Sendable {
        /// The byte count of an ARC presentation representation.
        public static var rawRepresentationByteCount: Int {
            4 * P256.compressedX962PointByteCount + 5 * P256.orderByteCount
        }

        internal var backing: ARC.Presentation<H2G>

        fileprivate init(backing: ARC.Presentation<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(
            rawRepresentation: D
        ) throws(ARCError) {
            self.backing = try withARCError(fallback: .invalidPresentation) {
                try ARC.Presentation.deserialize(
                    presentationData: rawRepresentation
                )
            }
        }

        public func writeRawRepresentation(
            into destination: UnsafeMutableRawBufferPointer
        ) throws(ARCError) {
            try withARCError(fallback: .internalFailure) {
                try self.backing.writeSerializedRepresentation(into: destination)
            }
        }

        /// Returns the ARC presentation representation.
        public func rawRepresentation() throws(ARCError) -> Data {
            try withARCError(fallback: .internalFailure) {
                try self.backing.serialize()
            }
        }

        /// The rate-limit tag carried by this presentation.
        public var tag: Tag {
            Tag(backing: self.backing.tag)
        }
    }
}

extension P256._ARCV1.PublicKey {
    internal func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D,
        m1: P256._ARCV1.H2G.G.Scalar,
        r1: P256._ARCV1.H2G.G.Scalar,
        r2: P256._ARCV1.H2G.G.Scalar
    ) throws -> P256._ARCV1.Precredential {
        let precedential = try ARC.Precredential(
            ciphersuite: P256._ARCV1.ciphersuite,
            m1: m1,
            requestContext: Data(requestContext),
            r1: r1,
            r2: r2,
            serverPublicKey: self.backing
        )
        return P256._ARCV1.Precredential(backing: precedential)
    }

    /// Prepare a credential request for a given request context.
    ///
    /// - Parameters:
    ///   - requestContext: Request context, agreed with the server.
    ///
    /// - Returns: A precredential containing the client secrets, and request to be sent to the server.
    public func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D
    ) throws(ARCError) -> P256._ARCV1.Precredential {
        try withARCError(fallback: .internalFailure) {
            try self.prepareCredentialRequest(
                requestContext: requestContext,
                m1: .randomNonzero(),
                r1: .randomNonzero(),
                r2: .randomNonzero()
            )
        }
    }
}

extension P256._ARCV1.PrivateKey {
    internal func issue(
        _ credentialRequest: P256._ARCV1.CredentialRequest,
        b: P256._ARCV1.H2G.G.Scalar
    ) throws -> P256._ARCV1.CredentialResponse {
        let response = try self.backing.respond(credentialRequest: credentialRequest.backing, b: b)
        return P256._ARCV1.CredentialResponse(backing: response)
    }

    /// Generate a credential response from a credential request.
    public func issue(
        _ credentialRequest: P256._ARCV1.CredentialRequest
    ) throws(ARCError) -> P256._ARCV1.CredentialResponse {
        try withARCError(fallback: .internalFailure) {
            try self.issue(credentialRequest, b: .randomNonzero())
        }
    }
}

extension P256._ARCV1.PublicKey {
    /// Create a credential from the issuer response.
    public func finalize(
        _ credentialResponse: P256._ARCV1.CredentialResponse,
        for precredential: P256._ARCV1.Precredential
    ) throws(ARCError) -> P256._ARCV1.Credential {
        try withARCError(fallback: .internalFailure) {
            let credential = try precredential.backing.makeCredential(
                credentialResponse: credentialResponse.backing
            )
            return P256._ARCV1.Credential(backing: credential)
        }
    }
}

extension P256._ARCV1.Credential {
    internal mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int,
        fixedNonce: Int?,
        a: P256._ARCV1.H2G.G.Scalar,
        r: P256._ARCV1.H2G.G.Scalar,
        z: P256._ARCV1.H2G.G.Scalar
    ) throws -> (presentation: P256._ARCV1.Presentation, nonce: Int) {
        let (presentation, nonce) = try self.backing.makePresentation(
            presentationContext: Data(context),
            presentationLimit: presentationLimit,
            a: a,
            r: r,
            z: z,
            optionalNonce: fixedNonce
        )
        return (P256._ARCV1.Presentation(backing: presentation), nonce)
    }

    /// Create a presentation to provide to a verifier.
    ///
    /// - Parameters:
    ///   - context: The presentation context agreed with the verifier.
    ///   - presentationLimit: The presentation limit to enforce.
    ///
    /// - Returns: A presentation of this credential.
    ///
    /// - Throws: An error if the presentation limit for this credential has been exceeded.
    public mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int
    ) throws(ARCError) -> (
        presentation: P256._ARCV1.Presentation,
        nonce: Int
    ) {
        try withARCError(fallback: .internalFailure) {
            try self.makePresentation(
                context: context,
                presentationLimit: presentationLimit,
                fixedNonce: nil,
                a: .randomNonzero(),
                r: .randomNonzero(),
                z: .randomNonzero()
            )
        }
    }
}

extension P256._ARCV1.PrivateKey {
    /// Verify a presentation is valid for a given attribute.
    ///
    /// Presentation verification includes checking that:
    /// 1. The presentation is for the expected request context.
    /// 2. The presentation is for the expected presentation context.
    /// 3. The presentation nonce is appropriate for the presentation limit.
    /// 4. The presentation proof is valid.
    ///
    /// - Parameters:
    ///   - presentation: The presentation to verify.
    ///   - requestContext: The expected request context encoded within the presentation.
    ///   - presentationContext: The expected presentation context encoded within the presentation.
    ///   - presentationLimit: The presentation limit to enforce.
    ///   - nonce: The expected nonce encoded within the presentation.
    ///
    /// - Returns: True if the presentation is valid, false otherwise.
    public func verify<D1: DataProtocol, D2: DataProtocol>(
        _ presentation: P256._ARCV1.Presentation,
        requestContext: D1,
        presentationContext: D2,
        presentationLimit: Int,
        nonce: Int
    ) throws(ARCError) -> Bool {
        try withARCError(fallback: .internalFailure) {
            try self.backing.verify(
                presentation: presentation.backing,
                requestContext: Data(requestContext),
                presentationContext: Data(presentationContext),
                presentationLimit: presentationLimit,
                nonce: nonce
            )
        }
    }
}

#endif  // !hasFeature(Embedded)
