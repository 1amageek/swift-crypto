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

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

// Test Vectors are coming from https://tools.ietf.org/html/rfc5869
class HKDFTests: XCTestCase {
    struct RFCTestVector: Codable {
        var hash: String
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var sharedInfo: [UInt8]
        var outputLength: Int
        var pseudoRandomKey: [UInt8]
        var outputKeyMaterial: [UInt8]
        
        enum CodingKeys: String, CodingKey {
            case hash = "Hash"
            case inputSecret = "IKM"
            case salt
            case sharedInfo = "info"
            case outputLength = "L"
            case pseudoRandomKey = "PRK"
            case outputKeyMaterial = "OKM"
        }
    }
    
    func expandExtractTesting<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) {
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()
        let (contiguousSharedInfo, discontiguousSharedInfo) = vector.sharedInfo.asDataProtocols()
        
        let PRK1 = HKDF<H>.extract(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                   salt: contiguousSalt)
        let PRK2 = HKDF<H>.extract(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                   salt: discontiguousSalt)
        
        let OKM1 = HKDF<H>.expand(pseudoRandomKey: PRK1, info: contiguousSharedInfo,
                                  outputByteCount: vector.outputLength)
        let OKM2 = HKDF<H>.expand(pseudoRandomKey: PRK1, info: discontiguousSharedInfo,
                                  outputByteCount: vector.outputLength)
        let OKM3 = HKDF<H>.expand(pseudoRandomKey: PRK2, info: contiguousSharedInfo,
                                  outputByteCount: vector.outputLength)
        let OKM4 = HKDF<H>.expand(pseudoRandomKey: PRK2, info: discontiguousSharedInfo,
                                  outputByteCount: vector.outputLength)
        
        XCTAssertEqual(Data(PRK1), Data(vector.pseudoRandomKey))
        XCTAssertEqual(Data(PRK2), Data(vector.pseudoRandomKey))
        
        let expectedOKM = SymmetricKey(data: vector.outputKeyMaterial)
        XCTAssertEqual(OKM1, expectedOKM)
        XCTAssertEqual(OKM2, expectedOKM)
        XCTAssertEqual(OKM3, expectedOKM)
        XCTAssertEqual(OKM4, expectedOKM)
    }
    
    func oneshotTesting<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) {
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()
        let (contiguousSharedInfo, discontiguousSharedInfo) = vector.sharedInfo.asDataProtocols()
        
        let OKM1 = HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                     salt: contiguousSalt,
                                     info: vector.sharedInfo, outputByteCount: vector.outputLength)
        let OKM2 = HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                     salt: contiguousSalt, info: vector.sharedInfo,
                                     outputByteCount: vector.outputLength)
        let OKM3 = HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                     salt: discontiguousSalt, info: contiguousSharedInfo,
                                     outputByteCount: vector.outputLength)
        let OKM4 = HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: vector.inputSecret),
                                     salt: discontiguousSalt, info: discontiguousSharedInfo,
                                     outputByteCount: vector.outputLength)
        
        let expectedOKM = SymmetricKey(data: vector.outputKeyMaterial)
        XCTAssertEqual(OKM1, expectedOKM)
        XCTAssertEqual(OKM2, expectedOKM)
        XCTAssertEqual(OKM3, expectedOKM)
        XCTAssertEqual(OKM4, expectedOKM)
    }
    
    func sharedSecretTesting<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) {
        let ss = SharedSecret(ss: SecureBytes(bytes: vector.inputSecret))
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()
        let (contiguousSharedInfo, discontiguousSharedInfo) = vector.sharedInfo.asDataProtocols()
        
        let firstKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: contiguousSalt,
                                                  sharedInfo: contiguousSharedInfo, outputByteCount: vector.outputLength)
        let secondKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: contiguousSalt,
                                                   sharedInfo: discontiguousSharedInfo, outputByteCount: vector.outputLength)
        let thirdKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: discontiguousSalt,
                                                  sharedInfo: contiguousSharedInfo, outputByteCount: vector.outputLength)
        let fourthKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: discontiguousSalt,
                                                   sharedInfo: discontiguousSharedInfo, outputByteCount: vector.outputLength)
        
        let expectedKey = SymmetricKey(data: vector.outputKeyMaterial)
        XCTAssertEqual(firstKey, expectedKey)
        XCTAssertEqual(secondKey, expectedKey)
        XCTAssertEqual(thirdKey, expectedKey)
        XCTAssertEqual(fourthKey, expectedKey)
    }
    
    func testRFCVector<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) {
        sharedSecretTesting(vector, hash: hash)
        oneshotTesting(vector, hash: hash)
        expandExtractTesting(vector, hash: hash)
    }

    func testOutputByteCountBounds() {
        let inputKeyMaterial = SymmetricKey(data: [UInt8](repeating: 0x0b, count: 22))
        let salt = Array(UInt8(0x00)...UInt8(0x0c))
        let info = Array(UInt8(0xf0)...UInt8(0xf9))
        let maximumOutputByteCount = SHA256.Digest.byteCount * 255
        let maximumLengthKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: maximumOutputByteCount
        )
        let expectedFinalBlock: [UInt8] = [
            0x76, 0xa3, 0xf7, 0x8b, 0xcf, 0xfe, 0x95, 0xfe,
            0xcf, 0x91, 0x92, 0x3c, 0x22, 0xad, 0x6e, 0xe6,
            0x4d, 0x48, 0xa6, 0xd1, 0xb9, 0x81, 0xd7, 0xe5,
            0x23, 0xd5, 0xc0, 0xf2, 0x21, 0x54, 0xee, 0x88,
        ]
        maximumLengthKey.withUnsafeBytes { bytes in
            XCTAssertEqual(bytes.count, maximumOutputByteCount)
            XCTAssertTrue(bytes.suffix(expectedFinalBlock.count).elementsEqual(expectedFinalBlock))
        }
    }
    
    func testRfcTestVectorsSHA1() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-5869-HKDF-SHA1") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }
        
        for vector in vectors {
            precondition(vector.hash == "SHA-1")
            self.testRFCVector(vector, hash: Insecure.SHA1.self)
        }
    }
    
    func testRfcTestVectorsSHA256() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-5869-HKDF-SHA256") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }
        
        for vector in vectors {
            precondition(vector.hash == "SHA-256")
            self.testRFCVector(vector, hash: SHA256.self)
        }
    }
}

#endif // canImport(CryptoKit)
