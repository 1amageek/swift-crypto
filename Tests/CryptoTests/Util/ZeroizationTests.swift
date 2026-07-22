//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if !canImport(CryptoKit)
@testable import Crypto
import Foundation
import XCTest

final class ZeroizationTests: XCTestCase {
    func testRawBufferZeroizationClearsTheEntireValue() {
        var value = (
            UInt64.max,
            UInt64.max,
            UInt64.max,
            UInt64.max
        )

        withUnsafeMutableBytes(of: &value) { bytes in
            bytes.zeroize()
        }

        XCTAssertEqual(value.0, 0)
        XCTAssertEqual(value.1, 0)
        XCTAssertEqual(value.2, 0)
        XCTAssertEqual(value.3, 0)
    }

    func testArrayZeroizationPreservesShapeAndClearsElements() {
        var bytes: [UInt8] = [1, 2, 3, 4, 5]

        bytes.zeroize()

        XCTAssertEqual(bytes, [0, 0, 0, 0, 0])
    }

    func testEmptyBufferZeroizationIsDefined() {
        var bytes: [UInt8] = []

        bytes.zeroize()

        XCTAssertTrue(bytes.isEmpty)
    }

    func testDataZeroizationPreservesShapeAndClearsElements() {
        var data = Data([1, 2, 3, 4, 5])

        data.zeroize()

        XCTAssertEqual(data, Data(repeating: 0, count: 5))
    }
}
#endif
