//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
import XCTest

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@testable import CryptoExtras

final class ECToolboxBoringSSLTests: XCTestCase {
    func testSharedArithmeticContextSerializesConcurrentOperations() async {
        await assertConcurrentArithmetic(P256.self)
        await assertConcurrentArithmetic(P384.self)
    }

    private func assertConcurrentArithmetic<Curve: HashToGroupCurve & Sendable>(
        _ curve: Curve.Type
    ) async {
        typealias Scalar = PrimeOrderCurveGroup<Curve>.Scalar
        let expectedContextIdentifier = ObjectIdentifier(Curve.arithmeticContext)
        let results = await withTaskGroup(of: ArithmeticResult.self, returning: [ArithmeticResult].self) { group in
            for _ in 0..<64 {
                group.addTask {
                    let lhs = Scalar.random
                    let rhs = Scalar.random
                    let sum = lhs + rhs
                    let restored = sum - rhs
                    let generator = PrimeOrderCurveGroup<Curve>.Element.generator
                    let point = lhs * generator
                    return ArithmeticResult(
                        contextIdentifier: ObjectIdentifier(Curve.arithmeticContext),
                        scalarRoundTripSucceeded: restored == lhs,
                        pointMultiplicationSucceeded: point == lhs * generator
                    )
                }
            }

            var results: [ArithmeticResult] = []
            results.reserveCapacity(64)
            for await result in group {
                results.append(result)
            }
            return results
        }

        XCTAssertEqual(results.count, 64)
        for result in results {
            XCTAssertEqual(result.contextIdentifier, expectedContextIdentifier)
            XCTAssertTrue(result.scalarRoundTripSucceeded)
            XCTAssertTrue(result.pointMultiplicationSucceeded)
        }
    }
}

private struct ArithmeticResult: Sendable {
    let contextIdentifier: ObjectIdentifier
    let scalarRoundTripSucceeded: Bool
    let pointMultiplicationSucceeded: Bool
}
