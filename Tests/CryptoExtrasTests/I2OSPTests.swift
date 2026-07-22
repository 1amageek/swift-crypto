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

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
@testable import CryptoExtras
import XCTest

final class I2OSPTests: XCTestCase {
    func testEncodesZero() {
        XCTAssertEqual(I2OSP(value: 0, outputByteCount: 1), Data([0]))
    }

    func testEncodesBigEndianWithLeadingZeroes() {
        XCTAssertEqual(
            I2OSP(value: 0x12_34, outputByteCount: 4),
            Data([0, 0, 0x12, 0x34])
        )
    }

    func testEncodesMaximumIntegerWithoutOverflow() {
        let byteCount = MemoryLayout<Int>.size
        let representation = I2OSP(
            value: Int.max,
            outputByteCount: byteCount
        )

        XCTAssertEqual(representation.count, byteCount)
        XCTAssertEqual(representation.first, 0x7f)
        XCTAssertTrue(representation.dropFirst().allSatisfy { $0 == 0xff })
    }
}
