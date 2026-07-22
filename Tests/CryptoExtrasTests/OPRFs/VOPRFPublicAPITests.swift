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
import CryptoExtras  // NOTE: No @testable import, because we want to test the public API.
#if canImport(Dispatch)
import Dispatch
#endif
import XCTest

final class VOPRFPublicAPITests: XCTestCase {

    private final class ByteAccessRecorder {
        var elementIteratorCreationCount = 0
        var elementAccessCount = 0
        var regionsAccessCount = 0
        var regionAccessCount = 0
        var regionBufferBorrowCount = 0

        var materializedByteCount: Int {
            self.elementAccessCount
        }
    }

    private final class ByteStorage {
        let bytes: [UInt8]

        init(_ bytes: [UInt8]) {
            self.bytes = bytes
        }
    }

    private struct ContiguousRegion: DataProtocol, ContiguousBytes {
        typealias Index = Int
        typealias Element = UInt8
        typealias SubSequence = ContiguousRegion
        typealias Regions = CollectionOfOne<ContiguousRegion>

        let storage: ByteStorage
        let bounds: Range<Int>
        let recorder: ByteAccessRecorder

        var startIndex: Int { self.bounds.lowerBound }
        var endIndex: Int { self.bounds.upperBound }

        subscript(index: Int) -> UInt8 {
            self.recorder.elementAccessCount += 1
            return self.storage.bytes[index]
        }

        subscript(bounds: Range<Int>) -> ContiguousRegion {
            precondition(
                bounds.lowerBound >= self.startIndex
                    && bounds.upperBound <= self.endIndex
            )
            return ContiguousRegion(
                storage: self.storage,
                bounds: bounds,
                recorder: self.recorder
            )
        }

        func index(after index: Int) -> Int {
            self.storage.bytes.index(after: index)
        }

        func index(before index: Int) -> Int {
            self.storage.bytes.index(before: index)
        }

        var regions: CollectionOfOne<ContiguousRegion> {
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
        typealias Element = ContiguousRegion

        let storage: ByteStorage
        let splitIndex: Int?
        let recorder: ByteAccessRecorder

        var startIndex: Int { 0 }
        var endIndex: Int { self.splitIndex == nil ? 1 : 2 }

        subscript(index: Int) -> ContiguousRegion {
            precondition(index >= self.startIndex && index < self.endIndex)
            self.recorder.regionAccessCount += 1
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
            return ContiguousRegion(
                storage: self.storage,
                bounds: bounds,
                recorder: self.recorder
            )
        }

        func index(after index: Int) -> Int { index + 1 }
        func index(before index: Int) -> Int { index - 1 }
    }

    private struct InstrumentedData: DataProtocol {
        typealias Index = Int
        typealias Element = UInt8
        typealias SubSequence = ArraySlice<UInt8>
        typealias Regions = RegionCollection

        let storage: ByteStorage
        let splitIndex: Int?
        let recorder: ByteAccessRecorder

        init(
            storage: [UInt8],
            splitIndex: Int?,
            recorder: ByteAccessRecorder
        ) {
            self.storage = ByteStorage(storage)
            self.splitIndex = splitIndex
            self.recorder = recorder
        }

        struct Iterator: IteratorProtocol {
            let data: InstrumentedData
            var index: Int

            mutating func next() -> UInt8? {
                guard self.index < self.data.endIndex else {
                    return nil
                }
                defer {
                    self.index = self.data.index(after: self.index)
                }
                return self.data[self.index]
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

        func index(after index: Int) -> Int {
            self.storage.bytes.index(after: index)
        }

        func index(before index: Int) -> Int {
            self.storage.bytes.index(before: index)
        }

        func makeIterator() -> Iterator {
            self.recorder.elementIteratorCreationCount += 1
            return Iterator(data: self, index: self.startIndex)
        }

        var regions: RegionCollection {
            self.recorder.regionsAccessCount += 1
            if let splitIndex {
                precondition(
                    splitIndex > self.startIndex
                        && splitIndex < self.endIndex
                )
            }
            return RegionCollection(
                storage: self.storage,
                splitIndex: self.splitIndex,
                recorder: self.recorder
            )
        }
    }

    private func representation(
        byteCount: Int,
        write: (UnsafeMutableRawBufferPointer) throws -> Void
    ) rethrows -> Data {
        var result = Data(count: byteCount)
        try result.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        return result
    }

    private func assertVOPRFError(
        _ expectedError: VOPRFError,
        file: StaticString = #filePath,
        line: UInt = #line,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            XCTFail("Expected \(expectedError)", file: file, line: line)
        } catch let error as VOPRFError {
            XCTAssertEqual(error, expectedError, file: file, line: line)
        } catch {
            XCTFail("Expected \(expectedError), received \(error)", file: file, line: line)
        }
    }

    private func assertOutputCapacityContract(
        byteCount: Int,
        expectedRepresentation: Data,
        file: StaticString = #filePath,
        line: UInt = #line,
        write: (UnsafeMutableRawBufferPointer) throws -> Void
    ) throws {
        var undersized = Data(count: byteCount - 1)
        assertVOPRFError(
            .insufficientOutputCapacity,
            file: file,
            line: line
        ) {
            try undersized.withUnsafeMutableBytes { destination in
                try write(destination)
            }
        }

        var exact = Data(count: byteCount)
        try exact.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        XCTAssertEqual(
            exact,
            expectedRepresentation,
            file: file,
            line: line
        )

        let sentinel = UInt8(0xa5)
        let trailingByteCount = 8
        var oversized = Data(
            repeating: sentinel,
            count: byteCount + trailingByteCount
        )
        try oversized.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        XCTAssertEqual(
            Data(oversized.prefix(byteCount)),
            expectedRepresentation,
            file: file,
            line: line
        )
        XCTAssertEqual(
            Data(oversized.suffix(trailingByteCount)),
            Data(repeating: sentinel, count: trailingByteCount),
            file: file,
            line: line
        )
    }

    func testEndToEndVOPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = try P384._VOPRF.PrivateKey()

        // [Client] Obtain public key (other initializers are available).
        let publicKey = privateKey.publicKey

        // [Client] Have a private input they wish to use.
        let privateInput = Data("This is some input data".utf8)

        // [Client] Blind the private input and send the blinded element to the server.
        let blindedInput = try publicKey.blind(privateInput)

        // [Client -> Server] Send the blinded element.
        let blindedElementBytes = try blindedInput.blindedElement.oprfRepresentation()

        // [Server] Receive the blinded element.
        let blindedElement = try P384._VOPRF.BlindedElement(oprfRepresentation: blindedElementBytes)

        // [Server] Blind evaluate the blinded element and send the evaluation, along with the proof, to the client.
        let blindEvaluation = try privateKey.evaluate(blindedElement)

        // [Server -> Client] Send the serialized blind evaluation.
        let blindEvaluationBytes = try blindEvaluation.rawRepresentation()

        // [Client] Receive the blind evaluation.
        let deserializedBlindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: blindEvaluationBytes)

        // [Client] Finalize the evaluation by verifying the proof and unblinding to produce the output.
        let finalizedOutput = try publicKey.finalize(blindedInput, using: deserializedBlindEvaluation)
        let directOutput = try privateKey.evaluate(privateInput)
        XCTAssertEqual(finalizedOutput, directOutput)
    }

    func testAccessToEvaluatedElementAndProof() throws {
        /// In RFC 9497, the `BlindEvaluate` routine returns both `evaluatedElement` and `proof`, which are both later
        /// provided to `Finalize`.
        ///
        /// For our API, these are bundled together into a `BlindEvaluation`, and since both are used in the final step,
        /// our `finalize` API takes the composite type too, to guide correct usage.
        ///
        /// However, for use cases that require distinct access to the evaluated element and the proof we also expose
        /// these properties as API.
        ///
        /// - See: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
        let vector = try XCTUnwrap(
            OPRFSuite.p384SHA384VOPRF().vectors.first { $0.batchSize == 1 }
        )
        let evaluatedElement = try Data(hexString: vector.evaluatedElements)
        let proof = try Data(hexString: XCTUnwrap(vector.proof).proof)
        let blindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: evaluatedElement + proof)
        XCTAssertEqual(
            try blindEvaluation.evaluatedElement.oprfRepresentation(),
            evaluatedElement
        )
        XCTAssertEqual(try blindEvaluation.proof.rawRepresentation(), proof)
    }

    func testEndToEndPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = try P384._VOPRF.PrivateKey()

        // [Server] Have an input they wish to use.
        let input = Data("This is some input data".utf8)

        // [Server] Compute the PRF for the input, without blinding or proof generation.
        let firstOutput = try privateKey.evaluate(input)
        let secondOutput = try privateKey.evaluate(input)
        XCTAssertEqual(firstOutput, secondOutput)
    }

    func testCallerOwnedRepresentationsMatchAllocatingConveniences() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let blindedInput = try publicKey.blind(Data("serialization".utf8))
        let blindEvaluation = try privateKey.evaluate(blindedInput.blindedElement)

        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.PrivateKey.rawRepresentationByteCount) {
                try privateKey.writeRawRepresentation(into: $0)
            },
            try privateKey.rawRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.PublicKey.oprfRepresentationByteCount) {
                try publicKey.writeOPRFRepresentation(into: $0)
            },
            try publicKey.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.BlindedElement.oprfRepresentationByteCount) {
                try blindedInput.blindedElement.writeOPRFRepresentation(into: $0)
            },
            try blindedInput.blindedElement.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.EvaluatedElement.oprfRepresentationByteCount) {
                try blindEvaluation.evaluatedElement.writeOPRFRepresentation(into: $0)
            },
            try blindEvaluation.evaluatedElement.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.Proof.rawRepresentationByteCount) {
                try blindEvaluation.proof.writeRawRepresentation(into: $0)
            },
            try blindEvaluation.proof.rawRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.BlindEvaluation.rawRepresentationByteCount) {
                try blindEvaluation.writeRawRepresentation(into: $0)
            },
            try blindEvaluation.rawRepresentation()
        )
    }

    func testCallerOwnedRepresentationCapacityContract() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let blindedInput = try publicKey.blind(Data("capacity".utf8))
        let blindEvaluation = try privateKey.evaluate(
            blindedInput.blindedElement
        )

        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.PrivateKey.rawRepresentationByteCount,
            expectedRepresentation: privateKey.rawRepresentation()
        ) {
            try privateKey.writeRawRepresentation(into: $0)
        }
        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.PublicKey.oprfRepresentationByteCount,
            expectedRepresentation: publicKey.oprfRepresentation()
        ) {
            try publicKey.writeOPRFRepresentation(into: $0)
        }
        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.BlindedElement.oprfRepresentationByteCount,
            expectedRepresentation: blindedInput.blindedElement.oprfRepresentation()
        ) {
            try blindedInput.blindedElement.writeOPRFRepresentation(into: $0)
        }
        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.EvaluatedElement.oprfRepresentationByteCount,
            expectedRepresentation: blindEvaluation.evaluatedElement.oprfRepresentation()
        ) {
            try blindEvaluation.evaluatedElement.writeOPRFRepresentation(into: $0)
        }
        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.Proof.rawRepresentationByteCount,
            expectedRepresentation: blindEvaluation.proof.rawRepresentation()
        ) {
            try blindEvaluation.proof.writeRawRepresentation(into: $0)
        }
        try assertOutputCapacityContract(
            byteCount: P384._VOPRF.BlindEvaluation.rawRepresentationByteCount,
            expectedRepresentation: blindEvaluation.rawRepresentation()
        ) {
            try blindEvaluation.writeRawRepresentation(into: $0)
        }
    }

    #if canImport(Dispatch)
    func testDirectEvaluationAcceptsDiscontiguousInput() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let input = Data("discontiguous VOPRF input".utf8)
        let (_, discontiguousInput) = Array(input).asDataProtocols(splitAt: 7)

        XCTAssertEqual(
            try privateKey.evaluate(input),
            try privateKey.evaluate(discontiguousInput)
        )
    }
    #endif

    func testSingleRegionInputsAvoidParentBufferMaterialization() throws {
        let suite = try OPRFSuite.p384SHA384VOPRF()
        let vector = try XCTUnwrap(
            suite.vectors.first {
                $0.batchSize == 1 && $0.inputs.count > 2
            }
        )
        let privateKey = try P384._VOPRF.PrivateKey(
            rawRepresentation: Data(hexString: suite.privateKey)
        )
        let publicKeyBytes = try privateKey.publicKey.oprfRepresentation()
        let publicKeyRecorder = ByteAccessRecorder()
        let publicKeyInput = InstrumentedData(
            storage: Array(publicKeyBytes),
            splitIndex: nil,
            recorder: publicKeyRecorder
        )

        let publicKey = try P384._VOPRF.PublicKey(
            oprfRepresentation: publicKeyInput
        )
        XCTAssertEqual(
            try publicKey.oprfRepresentation(),
            publicKeyBytes
        )
        XCTAssertEqual(publicKeyRecorder.materializedByteCount, 0)
        XCTAssertEqual(publicKeyRecorder.elementIteratorCreationCount, 0)
        XCTAssertEqual(publicKeyRecorder.regionsAccessCount, 1)
        XCTAssertEqual(publicKeyRecorder.regionAccessCount, 1)
        XCTAssertEqual(publicKeyRecorder.regionBufferBorrowCount, 1)

        let messageRecorder = ByteAccessRecorder()
        let messageBytes = Array(try Data(hexString: vector.inputs))
        let message = InstrumentedData(
            storage: messageBytes,
            splitIndex: nil,
            recorder: messageRecorder
        )
        let blindedInput = try publicKey.blind(message)
        XCTAssertEqual(messageRecorder.materializedByteCount, 0)
        XCTAssertEqual(messageRecorder.elementIteratorCreationCount, 0)
        XCTAssertEqual(messageRecorder.regionsAccessCount, 2)
        XCTAssertEqual(messageRecorder.regionAccessCount, 2)
        XCTAssertEqual(messageRecorder.regionBufferBorrowCount, 2)

        let evaluation = try privateKey.evaluate(
            blindedInput.blindedElement
        )
        let evaluationRecorder = ByteAccessRecorder()
        let evaluationInput = InstrumentedData(
            storage: Array(try evaluation.rawRepresentation()),
            splitIndex: nil,
            recorder: evaluationRecorder
        )
        let parsedEvaluation = try P384._VOPRF.BlindEvaluation(
            rawRepresentation: evaluationInput
        )
        XCTAssertEqual(evaluationRecorder.materializedByteCount, 0)
        XCTAssertEqual(evaluationRecorder.elementIteratorCreationCount, 0)
        XCTAssertEqual(evaluationRecorder.regionsAccessCount, 1)
        XCTAssertEqual(evaluationRecorder.regionAccessCount, 1)
        XCTAssertEqual(evaluationRecorder.regionBufferBorrowCount, 1)

        XCTAssertEqual(
            try publicKey.finalize(
                blindedInput,
                using: parsedEvaluation
            ).hexString,
            vector.outputs
        )

        let directRecorder = ByteAccessRecorder()
        let directInput = InstrumentedData(
            storage: messageBytes,
            splitIndex: nil,
            recorder: directRecorder
        )
        XCTAssertEqual(
            try privateKey.evaluate(directInput).hexString,
            vector.outputs
        )
        XCTAssertEqual(directRecorder.materializedByteCount, 0)
        XCTAssertEqual(directRecorder.elementIteratorCreationCount, 0)
        XCTAssertEqual(directRecorder.regionsAccessCount, 2)
        XCTAssertEqual(directRecorder.regionAccessCount, 2)
        XCTAssertEqual(directRecorder.regionBufferBorrowCount, 2)
    }

    func testMultiRegionInputsMaterializeExactlyOnce() throws {
        let suite = try OPRFSuite.p384SHA384VOPRF()
        let vector = try XCTUnwrap(
            suite.vectors.first {
                $0.batchSize == 1 && $0.inputs.count > 2
            }
        )
        let privateKey = try P384._VOPRF.PrivateKey(
            rawRepresentation: Data(hexString: suite.privateKey)
        )
        let publicKeyBytes = try privateKey.publicKey.oprfRepresentation()
        let publicKeyRecorder = ByteAccessRecorder()
        let publicKeyInput = InstrumentedData(
            storage: Array(publicKeyBytes),
            splitIndex: 17,
            recorder: publicKeyRecorder
        )

        let publicKey = try P384._VOPRF.PublicKey(
            oprfRepresentation: publicKeyInput
        )
        XCTAssertEqual(
            try publicKey.oprfRepresentation(),
            publicKeyBytes
        )
        XCTAssertEqual(
            publicKeyRecorder.materializedByteCount,
            publicKeyInput.count
        )
        XCTAssertEqual(publicKeyRecorder.elementIteratorCreationCount, 1)
        XCTAssertEqual(publicKeyRecorder.regionsAccessCount, 1)
        XCTAssertEqual(publicKeyRecorder.regionAccessCount, 2)
        XCTAssertEqual(publicKeyRecorder.regionBufferBorrowCount, 0)

        let messageBytes = Array(try Data(hexString: vector.inputs))
        let messageSplitIndex = messageBytes.count / 2
        let blindRecorder = ByteAccessRecorder()
        let blindInput = InstrumentedData(
            storage: messageBytes,
            splitIndex: messageSplitIndex,
            recorder: blindRecorder
        )
        let blindedInput = try publicKey.blind(blindInput)
        XCTAssertEqual(
            blindRecorder.materializedByteCount,
            blindInput.count
        )
        XCTAssertEqual(blindRecorder.elementIteratorCreationCount, 1)
        XCTAssertEqual(blindRecorder.regionsAccessCount, 2)
        XCTAssertEqual(blindRecorder.regionAccessCount, 4)
        XCTAssertEqual(blindRecorder.regionBufferBorrowCount, 2)

        let directRecorder = ByteAccessRecorder()
        let directInput = InstrumentedData(
            storage: messageBytes,
            splitIndex: messageSplitIndex,
            recorder: directRecorder
        )
        let directOutput = try privateKey.evaluate(directInput)
        XCTAssertEqual(directOutput.hexString, vector.outputs)
        XCTAssertEqual(
            directRecorder.materializedByteCount,
            directInput.count
        )
        XCTAssertEqual(directRecorder.elementIteratorCreationCount, 1)
        XCTAssertEqual(directRecorder.regionsAccessCount, 2)
        XCTAssertEqual(directRecorder.regionAccessCount, 4)
        XCTAssertEqual(directRecorder.regionBufferBorrowCount, 2)

        let evaluation = try privateKey.evaluate(
            blindedInput.blindedElement
        )
        let evaluationRecorder = ByteAccessRecorder()
        let evaluationInput = InstrumentedData(
            storage: Array(try evaluation.rawRepresentation()),
            splitIndex: 61,
            recorder: evaluationRecorder
        )
        let parsedEvaluation = try P384._VOPRF.BlindEvaluation(
            rawRepresentation: evaluationInput
        )
        XCTAssertEqual(
            evaluationRecorder.materializedByteCount,
            evaluationInput.count
        )
        XCTAssertEqual(evaluationRecorder.elementIteratorCreationCount, 1)
        XCTAssertEqual(evaluationRecorder.regionsAccessCount, 1)
        XCTAssertEqual(evaluationRecorder.regionAccessCount, 2)
        XCTAssertEqual(evaluationRecorder.regionBufferBorrowCount, 0)
        XCTAssertEqual(
            try publicKey.finalize(
                blindedInput,
                using: parsedEvaluation
            ).hexString,
            vector.outputs
        )
    }

    func testBlindedInputDoesNotRetainSourceBuffer() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        weak var sourceRecorder: ByteAccessRecorder?

        func makeBlindedInput() throws -> P384._VOPRF.BlindedInput {
            let recorder = ByteAccessRecorder()
            sourceRecorder = recorder
            let input = InstrumentedData(
                storage: Array("ephemeral VOPRF input".utf8),
                splitIndex: nil,
                recorder: recorder
            )
            return try publicKey.blind(input)
        }

        let blindedInput = try makeBlindedInput()
        XCTAssertNil(sourceRecorder)

        let evaluation = try privateKey.evaluate(
            blindedInput.blindedElement
        )
        XCTAssertFalse(
            try publicKey.finalize(blindedInput, using: evaluation).isEmpty
        )
    }

    func testZeroProofIsRejectedWithoutTerminating() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let input = Data("malicious proof".utf8)
        let blindedInput = try publicKey.blind(input)
        let validEvaluation = try privateKey.evaluate(blindedInput.blindedElement)
        let zeroProof = Data(
            repeating: 0,
            count: try validEvaluation.proof.rawRepresentation().count
        )
        let maliciousEvaluation = try P384._VOPRF.BlindEvaluation(
            rawRepresentation: try validEvaluation.evaluatedElement.oprfRepresentation() + zeroProof
        )

        assertVOPRFError(.invalidProof) {
            _ = try publicKey.finalize(blindedInput, using: maliciousEvaluation)
        }
    }

    func testPublicInputFailuresReturnTypedErrors() throws {
        let invalidCompressedPoint = Data(repeating: 0, count: 49)
        let invalidUncompressedPoint = Data(repeating: 0, count: 97)
        let zeroPrivateScalar = Data(
            repeating: 0,
            count: P384._VOPRF.PrivateKey.rawRepresentationByteCount
        )

        assertVOPRFError(.invalidPublicKey) {
            _ = try P384._VOPRF.PublicKey(
                oprfRepresentation: invalidCompressedPoint
            )
        }
        assertVOPRFError(.invalidElement) {
            _ = try P384._VOPRF.BlindedElement(
                oprfRepresentation: invalidCompressedPoint
            )
        }
        assertVOPRFError(.invalidElement) {
            _ = try P384._VOPRF.BlindedElement(
                oprfRepresentation: invalidUncompressedPoint
            )
        }
        assertVOPRFError(.invalidEncoding) {
            _ = try P384._VOPRF.BlindEvaluation(rawRepresentation: Data())
        }
        assertVOPRFError(.invalidPrivateKey) {
            _ = try P384._VOPRF.PrivateKey(
                rawRepresentation: zeroPrivateScalar
            )
        }
    }

    func testOversizedInputsReturnTypedErrors() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let oversizedInput = Data(repeating: 0, count: Int(UInt16.max) + 1)

        assertVOPRFError(.messageTooLong) {
            _ = try privateKey.publicKey.blind(oversizedInput)
        }
        assertVOPRFError(.messageTooLong) {
            _ = try privateKey.evaluate(oversizedInput)
        }
        assertVOPRFError(.keyInfoTooLong) {
            _ = try P384._VOPRF.PrivateKey(
                seed: Data(repeating: 0, count: 32),
                keyInfo: oversizedInput
            )
        }
        assertVOPRFError(.invalidSeed) {
            _ = try P384._VOPRF.PrivateKey(
                seed: Data(repeating: 0, count: 31),
                keyInfo: Data()
            )
        }
    }

    func testDeterministicPrivateKeyMatchesRFC9497() throws {
        let suite = try OPRFSuite.p384SHA384VOPRF()
        let privateKey = try P384._VOPRF.PrivateKey(
            seed: Data(hexString: suite.seed),
            keyInfo: Data(hexString: suite.keyInfo)
        )

        XCTAssertEqual(try privateKey.rawRepresentation().hexString, suite.privateKey)
        XCTAssertEqual(
            try privateKey.publicKey.oprfRepresentation().hexString,
            try XCTUnwrap(suite.publicKey)
        )
    }
}
