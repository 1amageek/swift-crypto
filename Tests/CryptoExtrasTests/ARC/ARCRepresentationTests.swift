//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
import CryptoExtras
import XCTest

final class ARCRepresentationTests: XCTestCase {
    private final class AccessRecorder {
        var elementAccessCount = 0
        var regionsAccessCount = 0
        var regionBufferBorrowCount = 0
    }

    private final class OwnedBytes {
        let bytes: [UInt8]

        init(_ bytes: [UInt8]) {
            self.bytes = bytes
        }
    }

    private struct BorrowedRegion: DataProtocol, ContiguousBytes {
        typealias Index = Int
        typealias Element = UInt8
        typealias SubSequence = BorrowedRegion
        typealias Regions = CollectionOfOne<BorrowedRegion>

        let storage: OwnedBytes
        let bounds: Range<Int>
        let recorder: AccessRecorder

        var startIndex: Int { self.bounds.lowerBound }
        var endIndex: Int { self.bounds.upperBound }

        subscript(index: Int) -> UInt8 {
            self.recorder.elementAccessCount += 1
            return self.storage.bytes[index]
        }

        subscript(bounds: Range<Int>) -> BorrowedRegion {
            precondition(
                bounds.lowerBound >= self.startIndex
                    && bounds.upperBound <= self.endIndex
            )
            return BorrowedRegion(
                storage: self.storage,
                bounds: bounds,
                recorder: self.recorder
            )
        }

        func index(after index: Int) -> Int { index + 1 }
        func index(before index: Int) -> Int { index - 1 }

        var regions: CollectionOfOne<BorrowedRegion> {
            CollectionOfOne(self)
        }

        func withUnsafeBytes<Result>(
            _ body: (UnsafeRawBufferPointer) throws -> Result
        ) rethrows -> Result {
            self.recorder.regionBufferBorrowCount += 1
            return try self.storage.bytes.withUnsafeBytes { storageBytes in
                try body(
                    UnsafeRawBufferPointer(
                        rebasing: storageBytes[self.bounds]
                    )
                )
            }
        }
    }

    private struct RegionCollection: BidirectionalCollection {
        typealias Index = Int
        typealias Element = BorrowedRegion

        let storage: OwnedBytes
        let splitIndex: Int?
        let recorder: AccessRecorder

        var startIndex: Int { 0 }
        var endIndex: Int { self.splitIndex == nil ? 1 : 2 }

        subscript(index: Int) -> BorrowedRegion {
            precondition(index >= self.startIndex && index < self.endIndex)
            let bounds: Range<Int>
            switch (index, self.splitIndex) {
            case (0, .none):
                bounds = self.storage.bytes.startIndex..<self.storage.bytes.endIndex
            case (0, .some(let splitIndex)):
                bounds = self.storage.bytes.startIndex..<splitIndex
            case (1, .some(let splitIndex)):
                bounds = splitIndex..<self.storage.bytes.endIndex
            default:
                preconditionFailure("Region index is outside the collection")
            }
            return BorrowedRegion(
                storage: self.storage,
                bounds: bounds,
                recorder: self.recorder
            )
        }

        func index(after index: Int) -> Int { index + 1 }
        func index(before index: Int) -> Int { index - 1 }
    }

    private struct RecordedRepresentation: DataProtocol {
        typealias Index = Int
        typealias Element = UInt8
        typealias SubSequence = ArraySlice<UInt8>
        typealias Regions = RegionCollection

        let storage: OwnedBytes
        let splitIndex: Int?
        let recorder: AccessRecorder

        init(
            bytes: [UInt8],
            splitIndex: Int?,
            recorder: AccessRecorder
        ) {
            self.storage = OwnedBytes(bytes)
            self.splitIndex = splitIndex
            self.recorder = recorder
        }

        struct Iterator: IteratorProtocol {
            let representation: RecordedRepresentation
            var index: Int

            mutating func next() -> UInt8? {
                guard self.index < self.representation.endIndex else {
                    return nil
                }
                defer { self.index += 1 }
                return self.representation[self.index]
            }
        }

        var startIndex: Int { self.storage.bytes.startIndex }
        var endIndex: Int { self.storage.bytes.endIndex }

        subscript(index: Int) -> UInt8 {
            self.recorder.elementAccessCount += 1
            return self.storage.bytes[index]
        }

        subscript(bounds: Range<Int>) -> ArraySlice<UInt8> {
            self.storage.bytes[bounds]
        }

        func index(after index: Int) -> Int { index + 1 }
        func index(before index: Int) -> Int { index - 1 }

        func makeIterator() -> Iterator {
            Iterator(representation: self, index: self.startIndex)
        }

        var regions: RegionCollection {
            self.recorder.regionsAccessCount += 1
            return RegionCollection(
                storage: self.storage,
                splitIndex: self.splitIndex,
                recorder: self.recorder
            )
        }
    }

    private func assertParserAccess<Value>(
        representation: Data,
        parse: (RecordedRepresentation) throws -> Value,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let bytes = Array(representation)

        let contiguousRecorder = AccessRecorder()
        weak var releasedStorage: OwnedBytes?
        var parsedValue: Value?
        do {
            let input = RecordedRepresentation(
                bytes: bytes,
                splitIndex: nil,
                recorder: contiguousRecorder
            )
            releasedStorage = input.storage
            parsedValue = try parse(input)
        }
        XCTAssertNotNil(parsedValue, file: file, line: line)
        XCTAssertNil(releasedStorage, file: file, line: line)
        XCTAssertEqual(
            contiguousRecorder.elementAccessCount,
            0,
            file: file,
            line: line
        )
        XCTAssertEqual(
            contiguousRecorder.regionsAccessCount,
            1,
            file: file,
            line: line
        )
        XCTAssertEqual(
            contiguousRecorder.regionBufferBorrowCount,
            1,
            file: file,
            line: line
        )

        let splitIndexes = Set([
            1,
            representation.count / 2,
            representation.count - 1,
        ])
        for splitIndex in splitIndexes {
            let splitRecorder = AccessRecorder()
            let input = RecordedRepresentation(
                bytes: bytes,
                splitIndex: splitIndex,
                recorder: splitRecorder
            )
            _ = try parse(input)
            XCTAssertEqual(
                splitRecorder.elementAccessCount,
                representation.count,
                file: file,
                line: line
            )
            XCTAssertEqual(
                splitRecorder.regionsAccessCount,
                1,
                file: file,
                line: line
            )
            XCTAssertEqual(
                splitRecorder.regionBufferBorrowCount,
                0,
                file: file,
                line: line
            )
        }
    }

    private func assertWriter(
        representation: Data,
        write: (UnsafeMutableRawBufferPointer) throws(ARCError) -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var exact = Data(repeating: 0xa5, count: representation.count)
        try exact.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        XCTAssertEqual(exact, representation, file: file, line: line)

        var oversized = Data(
            repeating: 0xa5,
            count: representation.count + 8
        )
        try oversized.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        XCTAssertEqual(
            oversized.prefix(representation.count),
            representation,
            file: file,
            line: line
        )
        XCTAssertEqual(
            oversized.suffix(8),
            Data(repeating: 0xa5, count: 8),
            file: file,
            line: line
        )

        var undersized = Data(
            repeating: 0xa5,
            count: representation.count - 1
        )
        do {
            try undersized.withUnsafeMutableBytes { destination in
                try write(destination)
            }
            XCTFail("Expected insufficient output capacity", file: file, line: line)
        } catch let error as ARCError {
            XCTAssertEqual(error, .insufficientOutputCapacity, file: file, line: line)
        } catch {
            XCTFail("Unexpected error: \(error)", file: file, line: line)
        }
        XCTAssertEqual(
            undersized,
            Data(repeating: 0xa5, count: representation.count - 1),
            file: file,
            line: line
        )
    }

    private func assertError(
        _ expectedError: ARCError,
        file: StaticString = #filePath,
        line: UInt = #line,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            XCTFail("Expected \(expectedError)", file: file, line: line)
        } catch let error as ARCError {
            XCTAssertEqual(error, expectedError, file: file, line: line)
        } catch {
            XCTFail("Unexpected error: \(error)", file: file, line: line)
        }
    }

    func testPublicParsersBorrowOrMaterializeOnce() throws {
        let privateKey = try P256._ARCV1.PrivateKey()
        let privateKeyBytes = try privateKey.rawRepresentation()
        try self.assertParserAccess(representation: privateKeyBytes) {
            try P256._ARCV1.PrivateKey(rawRepresentation: $0)
        }

        let publicKey = privateKey.publicKey
        let publicKeyBytes = try publicKey.rawRepresentation()
        try self.assertParserAccess(representation: publicKeyBytes) {
            try P256._ARCV1.PublicKey(rawRepresentation: $0)
        }

        let precredential = try publicKey.prepareCredentialRequest(
            requestContext: Data("request".utf8)
        )
        let requestBytes = try precredential.credentialRequest.rawRepresentation()
        try self.assertParserAccess(representation: requestBytes) {
            try P256._ARCV1.CredentialRequest(rawRepresentation: $0)
        }

        let response = try privateKey.issue(precredential.credentialRequest)
        let responseBytes = try response.rawRepresentation()
        try self.assertParserAccess(representation: responseBytes) {
            try P256._ARCV1.CredentialResponse(rawRepresentation: $0)
        }

        var credential = try publicKey.finalize(response, for: precredential)
        let credentialBytes = try credential.rawRepresentation()
        try self.assertParserAccess(representation: credentialBytes) {
            try P256._ARCV1.Credential(rawRepresentation: $0)
        }
        let presentation = try credential.makePresentation(
            context: Data("presentation".utf8),
            presentationLimit: 1
        ).presentation
        let presentationBytes = try presentation.rawRepresentation()
        try self.assertParserAccess(representation: presentationBytes) {
            try P256._ARCV1.Presentation(rawRepresentation: $0)
        }
    }

    func testPublicWritersUseCallerOwnedPrefix() throws {
        let privateKey = try P256._ARCV1.PrivateKey()
        try self.assertWriter(
            representation: privateKey.rawRepresentation(),
            write: privateKey.writeRawRepresentation
        )

        let publicKey = privateKey.publicKey
        try self.assertWriter(
            representation: publicKey.rawRepresentation(),
            write: publicKey.writeRawRepresentation
        )

        let precredential = try publicKey.prepareCredentialRequest(
            requestContext: Data("request".utf8)
        )
        try self.assertWriter(
            representation: precredential.credentialRequest.rawRepresentation(),
            write: precredential.credentialRequest.writeRawRepresentation
        )

        let response = try privateKey.issue(precredential.credentialRequest)
        try self.assertWriter(
            representation: response.rawRepresentation(),
            write: response.writeRawRepresentation
        )

        var credential = try publicKey.finalize(response, for: precredential)
        try self.assertWriter(
            representation: credential.rawRepresentation(),
            write: credential.writeRawRepresentation
        )
        let presentation = try credential.makePresentation(
            context: Data("presentation".utf8),
            presentationLimit: 1
        ).presentation
        try self.assertWriter(
            representation: presentation.rawRepresentation(),
            write: presentation.writeRawRepresentation
        )
        try self.assertWriter(
            representation: presentation.tag.rawRepresentation(),
            write: presentation.tag.writeRawRepresentation
        )
    }

    func testPublicRepresentationByteCountsMatchOutput() throws {
        let privateKey = try P256._ARCV1.PrivateKey()
        XCTAssertEqual(
            P256._ARCV1.PrivateKey.rawRepresentationByteCount,
            try privateKey.rawRepresentation().count
        )
        XCTAssertEqual(
            P256._ARCV1.PublicKey.rawRepresentationByteCount,
            try privateKey.publicKey.rawRepresentation().count
        )

        let precredential = try privateKey.publicKey.prepareCredentialRequest(
            requestContext: Data("request".utf8)
        )
        XCTAssertEqual(
            P256._ARCV1.CredentialRequest.rawRepresentationByteCount,
            try precredential.credentialRequest.rawRepresentation().count
        )
        let response = try privateKey.issue(precredential.credentialRequest)
        XCTAssertEqual(
            P256._ARCV1.CredentialResponse.rawRepresentationByteCount,
            try response.rawRepresentation().count
        )
        var credential = try privateKey.publicKey.finalize(
            response,
            for: precredential
        )
        XCTAssertEqual(
            try credential.rawRepresentationByteCount(),
            try credential.rawRepresentation().count
        )
        let presentation = try credential.makePresentation(
            context: Data("presentation".utf8),
            presentationLimit: 1
        ).presentation
        XCTAssertEqual(
            P256._ARCV1.Presentation.rawRepresentationByteCount,
            try presentation.rawRepresentation().count
        )
        XCTAssertEqual(
            P256._ARCV1.Tag.rawRepresentationByteCount,
            try presentation.tag.rawRepresentation().count
        )
    }

    func testMalformedRepresentationsProduceTypedErrors() throws {
        let privateKey = try P256._ARCV1.PrivateKey()
        let privateKeyBytes = try privateKey.rawRepresentation()
        self.assertError(.invalidPrivateKey) {
            _ = try P256._ARCV1.PrivateKey(
                rawRepresentation: privateKeyBytes.dropLast()
            )
        }
        for scalarIndex in 0..<4 {
            var zeroScalar = privateKeyBytes
            let start = scalarIndex * P256._ARCV1.PrivateKey.rawRepresentationByteCount / 4
            zeroScalar.replaceSubrange(
                start..<(start + P256._ARCV1.PrivateKey.rawRepresentationByteCount / 4),
                with: repeatElement(0, count: P256._ARCV1.PrivateKey.rawRepresentationByteCount / 4)
            )
            self.assertError(.invalidPrivateKey) {
                _ = try P256._ARCV1.PrivateKey(rawRepresentation: zeroScalar)
            }
        }

        let publicKey = privateKey.publicKey
        var invalidPublicKey = try publicKey.rawRepresentation()
        invalidPublicKey[invalidPublicKey.startIndex] = 0
        self.assertError(.invalidPublicKey) {
            _ = try P256._ARCV1.PublicKey(
                rawRepresentation: invalidPublicKey
            )
        }

        let precredential = try publicKey.prepareCredentialRequest(
            requestContext: Data("request".utf8)
        )
        var invalidRequest = try precredential.credentialRequest.rawRepresentation()
        let requestProofStart =
            2 * P256._ARCV1.Tag.rawRepresentationByteCount
        let scalarByteCount =
            P256._ARCV1.PrivateKey.rawRepresentationByteCount / 4
        invalidRequest.replaceSubrange(
            requestProofStart..<(requestProofStart + scalarByteCount),
            with: repeatElement(0xff, count: scalarByteCount)
        )
        self.assertError(.invalidCredentialRequest) {
            _ = try P256._ARCV1.CredentialRequest(
                rawRepresentation: invalidRequest
            )
        }

        let response = try privateKey.issue(precredential.credentialRequest)
        var invalidResponse = try response.rawRepresentation()
        invalidResponse[invalidResponse.startIndex] = 0
        self.assertError(.invalidCredentialResponse) {
            _ = try P256._ARCV1.CredentialResponse(
                rawRepresentation: invalidResponse
            )
        }

        var credential = try publicKey.finalize(response, for: precredential)
        var invalidCredential = try credential.rawRepresentation()
        invalidCredential.replaceSubrange(
            0..<scalarByteCount,
            with: repeatElement(0, count: scalarByteCount)
        )
        self.assertError(.invalidCredential) {
            _ = try P256._ARCV1.Credential(
                rawRepresentation: invalidCredential
            )
        }
        let presentation = try credential.makePresentation(
            context: Data("presentation".utf8),
            presentationLimit: 1
        ).presentation
        var invalidPresentation = try presentation.rawRepresentation()
        invalidPresentation[invalidPresentation.startIndex] = 0
        self.assertError(.invalidPresentation) {
            _ = try P256._ARCV1.Presentation(
                rawRepresentation: invalidPresentation
            )
        }
    }
}
