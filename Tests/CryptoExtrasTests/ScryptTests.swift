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
import XCTest
import Crypto
@testable import CryptoExtras

// Test Vectors are coming from https://tools.ietf.org/html/rfc7914
class ScryptTests: XCTestCase {
    private final class AccessRecorder {
        var elementAccessCount = 0
    }

    private struct SingleRegionInput: DataProtocol {
        typealias Index = Int
        typealias Element = UInt8
        typealias SubSequence = ArraySlice<UInt8>
        typealias Regions = CollectionOfOne<[UInt8]>

        let bytes: [UInt8]
        let recorder: AccessRecorder

        var startIndex: Int { self.bytes.startIndex }
        var endIndex: Int { self.bytes.endIndex }

        subscript(index: Int) -> UInt8 {
            self.recorder.elementAccessCount += 1
            return self.bytes[index]
        }

        subscript(bounds: Range<Int>) -> ArraySlice<UInt8> {
            self.bytes[bounds]
        }

        func index(after index: Int) -> Int { index + 1 }
        func index(before index: Int) -> Int { index - 1 }

        var regions: CollectionOfOne<[UInt8]> {
            CollectionOfOne(self.bytes)
        }
    }

    struct RFCTestVector: Codable {
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var rounds: Int
        var blockSize: Int
        var parallelism: Int
        var outputLength: Int
        var derivedKey: [UInt8]

        enum CodingKeys: String, CodingKey {
            case inputSecret = "P"
            case salt = "S"
            case rounds = "N"
            case blockSize = "r"
            case parallelism = "p"
            case outputLength = "dkLen"
            case derivedKey = "DK"
        }
    }

    func oneshotTesting(_ vector: RFCTestVector) throws {
        let (contiguousInput, discontiguousInput) = vector.inputSecret.asDataProtocols()
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()

        let DK1 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK2 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK3 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK4 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let expectedDK = SymmetricKey(data: vector.derivedKey)
        XCTAssertEqual(DK1, expectedDK)
        XCTAssertEqual(DK2, expectedDK)
        XCTAssertEqual(DK3, expectedDK)
        XCTAssertEqual(DK4, expectedDK)
    }

    func testRFCVector(_ vector: RFCTestVector) throws {
        try oneshotTesting(vector)
    }

    func testRfcTestVectors() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-7914-scrypt") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            try orFail { try self.testRFCVector(vector) }
        }
    }

    func testHonorsExactMaximumMemory() throws {
        let requiredMemory = 128 * 1 * (16 + 1 + 1)
        _ = try KDF.Scrypt.deriveKey(
            from: [UInt8]("password".utf8),
            salt: [UInt8]("salt".utf8),
            outputByteCount: 16,
            rounds: 16,
            blockSize: 1,
            parallelism: 1,
            maxMemory: requiredMemory
        )
    }

    func testRejectsInsufficientMaximumMemory() {
        let requiredMemory = 128 * 1 * (16 + 1 + 1)
        self.assertIncorrectParameter {
            try KDF.Scrypt.deriveKey(
                from: [UInt8]("password".utf8),
                salt: [UInt8]("salt".utf8),
                outputByteCount: 16,
                rounds: 16,
                blockSize: 1,
                parallelism: 1,
                maxMemory: requiredMemory - 1
            )
        }
    }

    func testRejectsInvalidParametersBeforeAllocation() {
        let parameters: [(Int, Int, Int, Int, Int?)] = [
            (0, 16, 1, 1, nil),
            (16, 1, 1, 1, nil),
            (16, 3, 1, 1, nil),
            (16, 16, 0, 1, nil),
            (16, 16, 1, 0, nil),
            (16, 65_536, 1, 1, nil),
            (16, 16, 1, 1 << 30, nil),
            (16, 16, 1, 1, -1),
        ]

        for (outputByteCount, rounds, blockSize, parallelism, maxMemory) in parameters {
            self.assertIncorrectParameter {
                try KDF.Scrypt.deriveKey(
                    from: [UInt8](),
                    salt: [UInt8](),
                    outputByteCount: outputByteCount,
                    rounds: rounds,
                    blockSize: blockSize,
                    parallelism: parallelism,
                    maxMemory: maxMemory
                )
            }
        }
    }

    func testBorrowsSingleRegionInputs() throws {
        let passwordRecorder = AccessRecorder()
        let saltRecorder = AccessRecorder()
        let password = SingleRegionInput(
            bytes: [UInt8]("password".utf8),
            recorder: passwordRecorder
        )
        let salt = SingleRegionInput(
            bytes: [UInt8]("salt".utf8),
            recorder: saltRecorder
        )

        _ = try KDF.Scrypt.deriveKey(
            from: password,
            salt: salt,
            outputByteCount: 16,
            rounds: 16,
            blockSize: 1,
            parallelism: 1
        )

        XCTAssertEqual(passwordRecorder.elementAccessCount, 0)
        XCTAssertEqual(saltRecorder.elementAccessCount, 0)
    }

    private func assertIncorrectParameter(
        _ operation: () throws -> SymmetricKey,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual(
                error as? CryptoKitError,
                CryptoKitError.incorrectParameterSize,
                file: file,
                line: line
            )
        }
    }
}
