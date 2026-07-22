//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
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

struct SegmentedValidationBytes: DataProtocol {
    typealias Index = Int
    typealias SubSequence = Data
    typealias Regions = [Data]

    let firstRegion: Data
    let secondRegion: Data

    init(firstRegion: [UInt8], secondRegion: [UInt8]) {
        self.firstRegion = Data(firstRegion)
        self.secondRegion = Data(secondRegion)
    }

    var startIndex: Int { 0 }
    var endIndex: Int { firstRegion.count + secondRegion.count }

    var regions: [Data] {
        [firstRegion, secondRegion]
    }

    subscript(position: Int) -> UInt8 {
        preconditionFailure("Segmented validation input was materialized through element access")
    }

    subscript(bounds: Range<Int>) -> Data {
        preconditionFailure("Segmented validation input was materialized through range access")
    }

    func index(after index: Int) -> Int {
        index + 1
    }

    func index(before index: Int) -> Int {
        index - 1
    }

    func distance(from start: Int, to end: Int) -> Int {
        end - start
    }

    func index(_ index: Int, offsetBy distance: Int) -> Int {
        index + distance
    }

    #if hasFeature(Embedded)
    func withUnsafeBytes<R, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        preconditionFailure("Segmented validation input was materialized as one contiguous buffer")
    }
    #else
    func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        preconditionFailure("Segmented validation input was materialized as one contiguous buffer")
    }
    #endif
}
