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
#else
import Foundation
#endif
import XCTest

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

enum ECDHTestErrors: Error {
    case PublicKeyFailure
    case ParseSPKIFailure
}

class NISTECDHTests: XCTestCase {
    func testInteropFIPSKeys() throws {
        var fipsKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
        for _ in 0...10_000 {
            fipsKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            
            // We ensure we have a key that's not compact representable. (Some FIPS keys are)
            if fipsKey.publicKey.compactRepresentation != nil {
                continue
            } else {
                break
            }
        }
        
        let compactKey = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
        
        XCTAssertNil(fipsKey.publicKey.compactRepresentation)
        XCTAssertNotNil(compactKey.publicKey.compactRepresentation)
        
        let ss1 = try orFail { try fipsKey.sharedSecretFromKeyAgreement(with: compactKey.publicKey) }
        let ss2 = try orFail { try compactKey.sharedSecretFromKeyAgreement(with: fipsKey.publicKey) }
        XCTAssertEqual(ss1, ss2)
        
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(compactRepresentation: fipsKey.publicKey.rawRepresentation))
        let compactRepresentation = try XCTUnwrap(compactKey.publicKey.compactRepresentation)
        XCTAssertNotNil(try P256.KeyAgreement.PublicKey(compactRepresentation: compactRepresentation))
    }
    
    func testWycheproof() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp256r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(
                        group: group,
                        privateKeys: P256.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P256.coordinateByteCount
                    )
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp384r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(
                        group: group,
                        privateKeys: P384.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P384.coordinateByteCount
                    )
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp521r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(
                        group: group,
                        privateKeys: P521.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P521.coordinateByteCount
                    )
                })
        }

        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp256r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(
                        group: group,
                        privateKeys: P256.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P256.coordinateByteCount
                    )
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp384r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(
                        group: group,
                        privateKeys: P384.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P384.coordinateByteCount
                    )
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp521r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(
                        group: group,
                        privateKeys: P521.KeyAgreement.PrivateKey.self,
                        coordinateByteCount: P521.coordinateByteCount
                    )
                })
        }
    }
    
    func testGroup<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement>(
        group: ECDHTestGroup,
        privateKeys: PrivKey.Type,
        coordinateByteCount: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for testVector in group.tests {
            do {
                let publicKeyBytes = try Array(hexString: testVector.publicKey)
                let publicKey = try PrivKey.PK(derBytes: publicKeyBytes)
                let privateKeyBytes = try paddedPrivateKey(
                    testVector.privateKey,
                    coordinateByteCount: coordinateByteCount
                )
                let privateKey = try PrivKey(rawRepresentation: privateKeyBytes)
                let agreement = try XCTUnwrap(publicKey as? PrivKey.PublicKey, file: file, line: line)
                let result = try privateKey.sharedSecretFromKeyAgreement(with: agreement)
                let expectedResult = try Array(hexString: testVector.shared)

                XCTAssertEqual(Array(result.ss), expectedResult, file: file, line: line)
            } catch ECDHTestErrors.PublicKeyFailure {
                XCTAssert(
                    testVector.flags.contains("CompressedPoint")
                        || testVector.result == "invalid"
                        || testVector.flags.contains("InvalidPublic")
                        || testVector.flags.contains("InvalidAsn"),
                    file: file,
                    line: line
                )
            } catch ECDHTestErrors.ParseSPKIFailure {
                XCTAssert(
                    testVector.flags.contains("InvalidAsn")
                        || testVector.flags.contains("UnnamedCurve"),
                    file: file,
                    line: line
                )
            } catch {
                if testVector.result == "valid" {
                    XCTAssert(
                        testVector.tcId == 31 || testVector.tcId == 20 || testVector.tcId == 25,
                        file: file,
                        line: line
                    )
                }
            }
        }
    }

    func testGroupPoint<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement>(
        group: ECDHTestGroup,
        privateKeys: PrivKey.Type,
        coordinateByteCount: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for testVector in group.tests {
            do {
                let publicKeyBytes = try Array(hexString: testVector.publicKey)
                let publicKey: PrivKey.PK
                if testVector.flags.contains("CompressedPoint") {
                    publicKey = try PrivKey.PK(compressedRepresentation: publicKeyBytes)
                } else {
                    publicKey = try PrivKey.PK(x963Representation: publicKeyBytes)
                }

                let privateKeyBytes = try paddedPrivateKey(
                    testVector.privateKey,
                    coordinateByteCount: coordinateByteCount
                )
                let privateKey = try PrivKey(rawRepresentation: privateKeyBytes)
                let agreement = try XCTUnwrap(publicKey as? PrivKey.PublicKey, file: file, line: line)
                let result = try privateKey.sharedSecretFromKeyAgreement(with: agreement)
                let expectedResult = try Array(hexString: testVector.shared)

                XCTAssertEqual(Array(result.ss), expectedResult, file: file, line: line)
                XCTAssertTrue(
                    testVector.result == "valid" || testVector.result == "acceptable",
                    file: file,
                    line: line
                )
            } catch {
                XCTAssertEqual(testVector.result, "invalid", file: file, line: line)
            }
        }
    }

    private func paddedPrivateKey(
        _ vector: String,
        coordinateByteCount: Int
    ) throws -> [UInt8] {
        var privateKeyBytes = [UInt8](repeating: 0, count: coordinateByteCount)
        let normalizedVector = vector.count.isMultiple(of: 2) ? vector : "0\(vector)"
        let vectorBytes = try Array(hexString: normalizedVector)

        if vectorBytes.count >= coordinateByteCount {
            privateKeyBytes = Array(vectorBytes.suffix(coordinateByteCount))
        } else {
            privateKeyBytes.replaceSubrange(
                (coordinateByteCount - vectorBytes.count)..<coordinateByteCount,
                with: vectorBytes
            )
        }
        return privateKeyBytes
    }
}

extension NISTECPublicKey {
    init(derBytes: [UInt8]) throws {
        let subjectPublicKeyInfo = try ASN1.SubjectPublicKeyInfo(asn1Encoded: derBytes)
        guard
            subjectPublicKeyInfo.algorithmIdentifier.algorithm
                == ASN1.ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey
        else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        do {
            try self.init(x963Representation: subjectPublicKeyInfo.key)
        } catch {
            throw ECDHTestErrors.PublicKeyFailure
        }
    }
}
#endif // canImport(CryptoKit)
