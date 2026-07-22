//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

func orFail<T>(file: StaticString = #filePath, line: UInt = #line, _ closure: () throws -> T) throws -> T {
    try closure()
}

func XCTAssertThrowsError<T, E: Error & Equatable>(
    _ expression: @autoclosure () throws -> T,
    error: E,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line)
{
    XCTAssertThrowsError(try expression(), message(), file: file, line: line) { foundError in
        XCTAssertEqual(foundError as? E, error, message(), file: file, line: line)
    }
}
