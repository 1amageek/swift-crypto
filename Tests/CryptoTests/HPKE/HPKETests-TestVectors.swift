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

let unsupportedKEMs: [UInt16] = [0x0021]

struct HPKETestEncryption: Codable {
    let aad: String
    let ct: String
    let nonce: String
    let pt: String
}

struct HPKETestVector: Codable {
    let mode: UInt8
    let kemIdentifier: UInt16
    let kdfIdentifier: UInt16
    let aeadIdentifier: UInt16
    
    let info: String
    let enc: String
    
    let ephemeralPrivateKey: String
    let recipientPrivateKey: String
    
    let ephemeralPublicKey: String
    let recipientPublicKey: String
    
    let senderPublicKey: String?
    
    let presharedKey: String?
    let presharedKeyIdentifier: String?
    
    let sharedSecret: String
    let secret: String
    
    let exporterSecret: String
    
    let encryptions: [HPKETestEncryption]

    enum CodingKeys: String, CodingKey {
        case mode
        case kemIdentifier = "kem_id"
        case kdfIdentifier = "kdf_id"
        case aeadIdentifier = "aead_id"
        case info
        case enc
        case ephemeralPrivateKey = "skEm"
        case recipientPrivateKey = "skRm"
        case ephemeralPublicKey = "pkEm"
        case recipientPublicKey = "pkRm"
        case senderPublicKey = "pkSm"
        case presharedKey = "psk"
        case presharedKeyIdentifier = "psk_id"
        case sharedSecret = "shared_secret"
        case secret
        case exporterSecret = "exporter_secret"
        case encryptions
    }
}

class HPKETestVectors: XCTestCase {
    
    func testVectors() throws {
        let bundle = Bundle.module
        let fileURL = try XCTUnwrap(
            bundle.url(forResource: "hpke-test-vectors", withExtension: "json")
        )
        let data = try orFail { try Data(contentsOf: fileURL) }
        let decoder = JSONDecoder()
        let testVectors = try orFail { try decoder.decode([HPKETestVector].self, from: data) }
        for testVector in testVectors {
            try validateTestVector(testVector)
        }
    }
    
    func validateTestVector(_ tv: HPKETestVector) throws {
        guard let ciphersuite = ciphersuiteFromValues(
            kemValue: tv.kemIdentifier,
            kdfValue: tv.kdfIdentifier,
            aeadValue: tv.aeadIdentifier
        ) else {
            if unsupportedKEMs.contains(tv.kemIdentifier) {
                print("Skipping unsupported KEM: \(tv.kemIdentifier)")
            } else {
                XCTFail(
                    "Ciphersuite could not be configured from input values "
                        + "kem:\(tv.kemIdentifier) kdf:\(tv.kdfIdentifier) aead:\(tv.aeadIdentifier)"
                )
            }
            return
        }
        
        let recipientPrivateKeyBytes = try Data(hexString: tv.recipientPrivateKey)
        
        switch ciphersuite.kem {
        case .P256_HKDF_SHA256:
            try testWithKEM(
                tv,
                ciphersuite: ciphersuite,
                skR: P256.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKeyBytes)
            )
        case .P384_HKDF_SHA384:
            try testWithKEM(
                tv,
                ciphersuite: ciphersuite,
                skR: P384.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKeyBytes)
            )
        case .P521_HKDF_SHA512:
            try testWithKEM(
                tv,
                ciphersuite: ciphersuite,
                skR: P521.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKeyBytes)
            )
        case .Curve25519_HKDF_SHA256:
            try testWithKEM(
                tv,
                ciphersuite: ciphersuite,
                skR: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKeyBytes)
            )
        case .XWingMLKEM768X25519:
            XCTFail("Unexpected X-Wing test vector")
        }
    }
    
    func testWithKEM<SK: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: SK) throws {
        let encapsulated = try Data(hexString: tv.enc)
                
        switch tv.mode {
        case HPKE.Mode.base.value, HPKE.Mode.psk.value: do {
            try testUnauthenticatedModesWithKeys(tv, ciphersuite: ciphersuite, skR: skR, encapsulated: encapsulated)
        }
        case HPKE.Mode.auth.value, HPKE.Mode.auth_psk.value: do {
            let senderPublicKey = try XCTUnwrap(tv.senderPublicKey)
            let pkSBytes = try Data(hexString: senderPublicKey)
            let pkS = try SK.PublicKey(pkSBytes, kem: ciphersuite.kem)
            
            try testAuthenticatedModesWithKeys(tv, ciphersuite: ciphersuite, skR: skR, encapsulated: encapsulated, pkS: pkS)
        }
        default:
            XCTFail("Test vectors contain an unsupported mode.")
        }
    }
    
    func testUnauthenticatedModesWithKeys<PrivateKey: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: PrivateKey, encapsulated: Data) throws {
        let infoBytes = try Data(hexString: tv.info)
                
        var recipient: HPKE.Recipient
        if tv.mode == HPKE.Mode.base.value {
            print(try skR.publicKey.hpkeRepresentation(kem: ciphersuite.kem).hexString)
            recipient = try HPKE.Recipient(
                privateKey: skR,
                ciphersuite: ciphersuite,
                info: infoBytes,
                encapsulatedKey: encapsulated
            )
        } else {
            let presharedKey = try XCTUnwrap(tv.presharedKey)
            let presharedKeyIdentifier = try XCTUnwrap(tv.presharedKeyIdentifier)
            let psk = try SymmetricKey(data: Data(hexString: presharedKey))
            let pskIdentifierBytes = try Data(hexString: presharedKeyIdentifier)
            recipient = try HPKE.Recipient(
                privateKey: skR,
                ciphersuite: ciphersuite,
                info: infoBytes,
                encapsulatedKey: encapsulated,
                presharedKey: psk,
                presharedKeyIdentifier: pskIdentifierBytes
            )
        }
        
        XCTAssertEqual(recipient.exporterSecret.withUnsafeBytes { Data($0) }.hexString, tv.exporterSecret)
        try testEncryptions(tv.encryptions, with: &recipient)
    }
    
    func testAuthenticatedModesWithKeys<SK: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: SK, encapsulated: Data, pkS: SK.PublicKey) throws {
        let infoBytes = try Data(hexString: tv.info)
        
        var recipient: HPKE.Recipient
        if tv.mode == HPKE.Mode.auth.value {
            recipient = try HPKE.Recipient(
                privateKey: skR,
                ciphersuite: ciphersuite,
                info: infoBytes,
                encapsulatedKey: encapsulated,
                authenticatedBy: pkS
            )
        } else {
            let presharedKey = try XCTUnwrap(tv.presharedKey)
            let presharedKeyIdentifier = try XCTUnwrap(tv.presharedKeyIdentifier)
            let psk = try SymmetricKey(data: Data(hexString: presharedKey))
            let pskIdentifierBytes = try Data(hexString: presharedKeyIdentifier)
            recipient = try HPKE.Recipient(
                privateKey: skR,
                ciphersuite: ciphersuite,
                info: infoBytes,
                encapsulatedKey: encapsulated,
                authenticatedBy: pkS,
                presharedKey: psk,
                presharedKeyIdentifier: pskIdentifierBytes
            )
        }

        XCTAssertEqual(recipient.exporterSecret.withUnsafeBytes { Data($0) }.hexString, tv.exporterSecret)
        try testEncryptions(tv.encryptions, with: &recipient)
    }
    
    func testEncryptions(_ encryptions: [HPKETestEncryption], with recipient: inout HPKE.Recipient) throws {
        for encryption in encryptions {
            let ct = try Data(hexString: encryption.ct)
            let aad = try Data(hexString: encryption.aad)
            let pt = try Data(hexString: encryption.pt)
            
            XCTAssertEqual(try recipient.open(ct, authenticating: aad), pt)
        }
    }
}

private func ciphersuiteFromValues(kemValue: UInt16,
                                   kdfValue: UInt16,
                                   aeadValue: UInt16) -> HPKE.Ciphersuite? {
    let kem = kemFromValue(value: kemValue)
    let kdf = kdfFromValue(value: kdfValue)
    let aead = aeadFromValue(value: aeadValue)
    
    guard let kem, let kdf, let aead else {
        return nil
    }
    return HPKE.Ciphersuite(kem: kem, kdf: kdf, aead: aead)
}

private func kemFromValue(value: UInt16) -> HPKE.KEM? {
    var kemValues = HPKE.KEM.allCases
    kemValues = kemValues.filter { value == $0.value }
    return kemValues.first
}

private func kdfFromValue(value: UInt16) -> HPKE.KDF? {
    var kdfValues = HPKE.KDF.allCases
    kdfValues = kdfValues.filter { value == $0.value }
    return kdfValues.first
}

private func aeadFromValue(value: UInt16) -> HPKE.AEAD? {
    var aeadValues = HPKE.AEAD.allCases
    aeadValues = aeadValues.filter { value == $0.value }
    return aeadValues.first
}

#endif // canImport(CryptoKit)
