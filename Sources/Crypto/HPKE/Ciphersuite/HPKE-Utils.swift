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

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif


#if canImport(CryptoKit)
import CryptoKit
#else



internal func I2OSP(value: Int, outputByteCount: Int) -> Data {
    precondition(outputByteCount > 0, "Cannot I2OSP with no output length.")
    precondition(value >= 0, "I2OSP requires a non-null value.")
    
    var significantValue = max(value, 1)
    var requiredBytes = 0
    repeat {
        requiredBytes += 1
        significantValue >>= 8
    } while significantValue > 0
    
    precondition(outputByteCount >= requiredBytes)
    
    var data = Data(repeating: 0, count: outputByteCount)
    
    for i in (outputByteCount - requiredBytes)...(outputByteCount - 1) {
        data[i] = UInt8(truncatingIfNeeded: (value >> (8 * (outputByteCount - 1 - i))))
    }
    
    return data
}

#endif // canImport(CryptoKit)
