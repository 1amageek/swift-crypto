import Foundation
import XCTest
@testable import Crypto
import SSLCrypto

final class PureSwiftBackendTests: XCTestCase {
    func testAESGCMNISTVector() throws {
        let key = SymmetricKey(data: Data(hex: "00000000000000000000000000000000"))
        let nonce = try AES.GCM.Nonce(data: Data(hex: "000000000000000000000000"))
        let plaintext = Data(hex: "00000000000000000000000000000000")
        let expectedCiphertext = Data(hex: "0388dace60b6a392f328c2b971b2fe78")
        let expectedTag = Data(hex: "ab6e47d42cec13bdf53a67b21257bddf")

        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        XCTAssertEqual(sealed.ciphertext, expectedCiphertext)
        XCTAssertEqual(sealed.tag, expectedTag)
        XCTAssertEqual(try AES.GCM.open(sealed, using: key), plaintext)
    }

    func testChaChaPolyRFC8439RoundTripAndAuthenticationFailure() throws {
        let key = SymmetricKey(data: Data(hex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
        let nonce = try ChaChaPoly.Nonce(data: Data(hex: "070000004041424344454647"))
        let authenticatedData = Data(hex: "50515253c0c1c2c3c4c5c6c7")
        let plaintext = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)

        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: authenticatedData
        )
        XCTAssertEqual(
            try ChaChaPoly.open(sealed, using: key, authenticating: authenticatedData),
            plaintext
        )

        var tampered = sealed.combined
        tampered[tampered.startIndex] ^= 1
        let tamperedBox = try ChaChaPoly.SealedBox(combined: tampered)
        XCTAssertThrowsError(try ChaChaPoly.open(tamperedBox, using: key, authenticating: authenticatedData))
    }

    func testX25519PureSwiftKeyAgreement() throws {
        let alice = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let bob = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))

        XCTAssertEqual(alice.publicKey.rawRepresentation.count, 32)
        XCTAssertEqual(bob.publicKey.rawRepresentation.count, 32)
        let aliceSecret = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        let bobSecret = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
        XCTAssertEqual(aliceSecret, bobSecret)
    }

    func testEd25519RFC8032Vector() throws {
        let seed = Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let expectedPublicKey = Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let expectedSignature = Data(hex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

        let direct = try seed.withUnsafeBytes { raw in
            let key = try SSLCrypto.Ed25519PrivateKey(seed: Span(_unsafeElements: raw.bindMemory(to: UInt8.self)))
            return Data(try key.sign(message: Span(_unsafeElements: UnsafeBufferPointer(start: nil, count: 0))))
        }
        XCTAssertEqual(direct, expectedSignature)

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        XCTAssertEqual(privateKey.rawRepresentation, seed)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, expectedPublicKey)
        let facadeSignature = try privateKey.signature(for: Data())
        XCTAssertTrue(privateKey.publicKey.isValidSignature(facadeSignature, for: Data()))
    }

    func testP384ECDSAVerificationAndMutation() throws {
        let publicKey = try P384.Signing.PublicKey(x963Representation: Data(hex:
            "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A"
            + "385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292"
            + "DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C9"
            + "0EA0E5F"))
        let digest = SHA384.hash(data: Array("abc".utf8))
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: Data(hex:
            "657A108BD5709DAD00F6FDD003137020A72F916199CE3F488A0C1154EC9F989"
            + "6D716232B4980EE345D13F17635BB1C9003AEB5FD9BE3D8F0BFFA1331F490F2"
            + "F82CD4335CABD5ABD764D7EC991477E59AE6EDA6475AD5E9C58732E06EB7CA6"
            + "871"))

        XCTAssertTrue(publicKey.isValidSignature(signature, for: digest))
        var mutatedBytes = signature.rawRepresentation
        mutatedBytes[mutatedBytes.startIndex] ^= 1
        let mutated = try P384.Signing.ECDSASignature(rawRepresentation: mutatedBytes)
        XCTAssertFalse(publicKey.isValidSignature(mutated, for: digest))
    }

    func testP521ECDSAVerificationAndMutation() throws {
        let publicKey = try P521.Signing.PublicKey(x963Representation: Data(hex:
            "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B"
            + "4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31"
            + "C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817"
            + "AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C2408"
            + "8BE94769FD16650"))
        let digest = SHA512.hash(data: Array("abc".utf8))
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: Data(hex:
            "00EF935737F1391BDC574E11C9D1769D3454E8A1611299843931BA10D213CF2"
            + "4FEE3EC80C6B3AF5C1E9A173775BB57CC52F5AD659A2D670D40E113D7E95E5"
            + "C97D78100C3DA0810F3AF0A3D2DF980C22F7F46E451F4DDCE7557871ACCC9B"
            + "EEB36A10C26BAF3DBE393ACFCEDDA5EDAAB9812DA9F2E05B6A174A4FDBD2FE"
            + "D52ECFFE1503BEF"))

        XCTAssertTrue(publicKey.isValidSignature(signature, for: digest))
        var mutatedBytes = signature.rawRepresentation
        mutatedBytes[mutatedBytes.index(before: mutatedBytes.endIndex)] ^= 1
        let mutated = try P521.Signing.ECDSASignature(rawRepresentation: mutatedBytes)
        XCTAssertFalse(publicKey.isValidSignature(mutated, for: digest))
    }

    func testP384AndP521PureSwiftKeyAgreementAndSigning() throws {
        let p384Scalar = Data(scalarData(count: 48, value: 1))
        let p384PeerScalar = Data(scalarData(count: 48, value: 2))
        let p384Private = try P384.KeyAgreement.PrivateKey(rawRepresentation: p384Scalar)
        let p384Peer = try P384.KeyAgreement.PrivateKey(rawRepresentation: p384PeerScalar)
        let p384Secret = try p384Private.sharedSecretFromKeyAgreement(with: p384Peer.publicKey)
        let p384PeerSecret = try p384Peer.sharedSecretFromKeyAgreement(with: p384Private.publicKey)
        XCTAssertEqual(p384Secret, p384PeerSecret)

        let p384Signing = try P384.Signing.PrivateKey(rawRepresentation: p384Scalar)
        let p384Digest = SHA384.hash(data: Data("pure-swift-p384".utf8))
        let p384Signature = try p384Signing.signature(for: p384Digest)
        XCTAssertTrue(p384Signing.publicKey.isValidSignature(p384Signature, for: p384Digest))

        let p521Scalar = Data(scalarData(count: 66, value: 1))
        let p521PeerScalar = Data(scalarData(count: 66, value: 2))
        let p521Private = try P521.KeyAgreement.PrivateKey(rawRepresentation: p521Scalar)
        let p521Peer = try P521.KeyAgreement.PrivateKey(rawRepresentation: p521PeerScalar)
        let p521Secret = try p521Private.sharedSecretFromKeyAgreement(with: p521Peer.publicKey)
        let p521PeerSecret = try p521Peer.sharedSecretFromKeyAgreement(with: p521Private.publicKey)
        XCTAssertEqual(p521Secret, p521PeerSecret)

        let p521Signing = try P521.Signing.PrivateKey(rawRepresentation: p521Scalar)
        let p521Digest = SHA512.hash(data: Data("pure-swift-p521".utf8))
        let p521Signature = try p521Signing.signature(for: p521Digest)
        XCTAssertTrue(p521Signing.publicKey.isValidSignature(p521Signature, for: p521Digest))
    }
}

private extension Data {
    init(hex: String) {
        precondition(hex.count.isMultiple(of: 2))
        let bytes = Array(hex.utf8)
        var decoded: [UInt8] = []
        decoded.reserveCapacity(bytes.count / 2)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let pair = String(decoding: bytes[index..<(index + 2)], as: UTF8.self)
            decoded.append(UInt8(pair, radix: 16)!)
        }
        self.init(decoded)
    }

}

private func scalarData(count: Int, value: UInt8) -> [UInt8] {
    var scalar = [UInt8](repeating: 0, count: count)
    scalar[count - 1] = value
    return scalar
}
