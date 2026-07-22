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
package func withUnsafeBytes<Bytes: ContiguousBytes, Result>(
    of bytes: Bytes,
    _ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> Result
) throws(CryptoBoringWrapperError) -> Result {
    #if !canImport(FoundationEssentials) && !canImport(Foundation)
    return try bytes.withUnsafeBytes(body)
    #else
    do {
        return try bytes.withUnsafeBytes { buffer in
            try body(buffer)
        }
    } catch let wrapperError as CryptoBoringWrapperError {
        throw wrapperError
    } catch {
        throw CryptoBoringWrapperError.internalBoringSSLError()
    }
    #endif
}

#if canImport(FoundationEssentials) || canImport(Foundation)
@usableFromInline
package func withUnsafeMutableBytes<Result>(
    of data: inout Data,
    _ body: (UnsafeMutableRawBufferPointer) throws(CryptoBoringWrapperError) -> Result
) throws(CryptoBoringWrapperError) -> Result {
    #if hasFeature(Embedded) && !canImport(FoundationEssentials) && !canImport(Foundation)
    return try data.withUnsafeMutableBytes(body)
    #else
    do {
        return try data.withUnsafeMutableBytes { buffer in
            try body(buffer)
        }
    } catch let wrapperError as CryptoBoringWrapperError {
        throw wrapperError
    } catch {
        throw CryptoBoringWrapperError.internalBoringSSLError()
    }
    #endif
}
#endif
