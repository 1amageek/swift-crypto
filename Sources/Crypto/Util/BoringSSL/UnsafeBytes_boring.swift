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

@usableFromInline
package func withUnsafeBytes<Bytes: ContiguousBytes, Result, E: Error>(
    of bytes: Bytes,
    _ body: (UnsafeRawBufferPointer) throws(E) -> Result
) throws(E) -> Result {
    #if !canImport(FoundationEssentials) && !canImport(Foundation)
    return try bytes.withUnsafeBytes(body)
    #else
    do {
        return try bytes.withUnsafeBytes { buffer in
            try body(buffer)
        }
    } catch let typedError as E {
        throw typedError
    } catch {
        preconditionFailure("Unexpected error type escaped ContiguousBytes.withUnsafeBytes")
    }
    #endif
}

@usableFromInline
package func withContiguousBytes<Bytes: DataProtocol, Result, E: Error>(
    of bytes: Bytes,
    _ body: (UnsafeRawBufferPointer) throws(E) -> Result
) throws(E) -> Result {
    #if !canImport(FoundationEssentials) && !canImport(Foundation)
    var regions = bytes.regions.makeIterator()
    guard let firstRegion = regions.next() else {
        return try body(UnsafeRawBufferPointer(start: nil, count: 0))
    }
    if regions.next() == nil {
        return try firstRegion.withUnsafeBytes(body)
    }
    return try Array(bytes).withUnsafeBytes(body)
    #else
    do {
        var regions = bytes.regions.makeIterator()
        guard let firstRegion = regions.next() else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
        if regions.next() == nil {
            return try firstRegion.withUnsafeBytes { buffer in
                try body(buffer)
            }
        }
        return try Array(bytes).withUnsafeBytes { buffer in
            try body(buffer)
        }
    } catch let typedError as E {
        throw typedError
    } catch {
        preconditionFailure("Unexpected error type escaped DataProtocol.withUnsafeBytes")
    }
    #endif
}

@usableFromInline
func cryptoData<Bytes: ContiguousBytes>(_ bytes: Bytes) -> Data {
    bytes.withUnsafeBytes { buffer in
        guard buffer.count > 0 else {
            return Data()
        }
        return Data(bytes: buffer.baseAddress!, count: buffer.count)
    }
}
