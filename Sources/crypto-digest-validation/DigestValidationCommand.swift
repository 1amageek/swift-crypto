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

@main
struct DigestValidationCommand {
    static func main() async {
        validate(Insecure.MD5.self, expectedHex: "900150983cd24fb0d6963f7d28e17f72")
        validate(Insecure.SHA1.self, expectedHex: "a9993e364706816aba3e25717850c26c9cd0d89d")
        validate(SHA256.self, expectedHex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        validate(
            SHA384.self,
            expectedHex: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
        validate(
            SHA512.self,
            expectedHex: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        #if SWIFT_CRYPTO_PURE_SWIFT
        validatePureSwiftNISTVerification()
        #endif
        #if !canImport(CryptoKit)
        validateSHA256Boundaries()
        await validateConcurrentSHA256Copies()
        validate(SHA3_256.self, expectedHex: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        validate(
            SHA3_384.self,
            expectedHex: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        )
        validate(
            SHA3_512.self,
            expectedHex: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
        #endif
        print("Digest validation passed")
    }

    private static func validate<Algorithm: HashFunction>(
        _ algorithm: Algorithm.Type,
        expectedHex: String
    ) {
        let message: [UInt8] = [0x61, 0x62, 0x63]
        let expected = decodeHex(expectedHex)
        let digest = algorithm.hash(data: message)
        precondition(digest.elementsEqual(expected))

        var first = algorithm.init()
        first.update(data: [0x01, 0x02, 0x03, 0x04])
        var second = first
        first.update(data: [0x05])
        second.update(data: [0x06])

        let firstDigest = first.finalize()
        let secondDigest = second.finalize()
        precondition(
            firstDigest.elementsEqual(
                algorithm.hash(data: [0x01, 0x02, 0x03, 0x04, 0x05])
            )
        )
        precondition(
            secondDigest.elementsEqual(
                algorithm.hash(data: [0x01, 0x02, 0x03, 0x04, 0x06])
            )
        )
        precondition(!firstDigest.elementsEqual(secondDigest))
        precondition(first.finalize().elementsEqual(firstDigest))

        var multiBlockMessage: [UInt8] = []
        multiBlockMessage.reserveCapacity(algorithm.blockByteCount * 3 + 17)
        for index in 0..<(algorithm.blockByteCount * 3 + 17) {
            multiBlockMessage.append(UInt8(truncatingIfNeeded: index &* 31))
        }

        let oneShotDigest = algorithm.hash(data: multiBlockMessage)
        let rawSpanDigest = multiBlockMessage.withUnsafeBytes { input in
            algorithm.hash(bytes: input.bytes)
        }
        precondition(rawSpanDigest.elementsEqual(oneShotDigest))

        var splitHasher = algorithm.init()
        multiBlockMessage.withUnsafeBytes { input in
            var offset = 0
            var chunkByteCount = 1
            while offset < input.count {
                let end = min(offset + chunkByteCount, input.count)
                splitHasher.update(
                    bufferPointer: UnsafeRawBufferPointer(rebasing: input[offset..<end])
                )
                offset = end
                chunkByteCount = chunkByteCount == 17 ? 1 : chunkByteCount + 1
            }
        }
        precondition(splitHasher.finalize().elementsEqual(oneShotDigest))
    }

    #if !canImport(CryptoKit)
    private static func validateSHA256Boundaries() {
        let inputByteCounts = [
            0, 1, 55, 56, 57, 63, 64, 65,
            119, 120, 121, 127, 128, 129,
            255, 256, 257, 1_023, 1_024, 1_025,
            4_095, 4_096, 4_097,
        ]
        let chunkByteCounts = [1, 7, 55, 64, 65, 127]

        for inputByteCount in inputByteCounts {
            let input = makeSHA256Input(byteCount: inputByteCount)
            let expected = SHA256.hash(data: input)
            precondition(
                SHA256.hash(bytes: input.span.bytes).elementsEqual(expected),
                "SHA-256 RawSpan boundary validation failed"
            )

            input.withUnsafeBytes { inputBytes in
                for chunkByteCount in chunkByteCounts {
                    var hasher = SHA256()
                    var offset = 0
                    while offset < inputBytes.count {
                        let end = min(offset + chunkByteCount, inputBytes.count)
                        hasher.update(
                            bufferPointer: UnsafeRawBufferPointer(
                                rebasing: inputBytes[offset..<end]
                            )
                        )
                        offset = end
                    }
                    precondition(
                        hasher.finalize().elementsEqual(expected),
                        "SHA-256 incremental boundary validation failed"
                    )
                }
            }
        }
    }

    private static func validateConcurrentSHA256Copies() async {
        let prefix = makeSHA256Input(byteCount: 193)
        var prefixState = SHA256()
        prefixState.update(data: prefix)
        let sharedPrefixState = prefixState

        await withTaskGroup(of: Void.self) { group in
            for taskIndex in 0..<32 {
                let suffix = makeSHA256Input(byteCount: 55 + taskIndex)
                group.addTask {
                    var localState = sharedPrefixState
                    localState.update(data: suffix)
                    let expected = SHA256.hash(data: prefix + suffix)
                    precondition(
                        localState.finalize().elementsEqual(expected),
                        "Concurrent SHA-256 copy-on-write validation failed"
                    )
                }
            }
        }
    }

    private static func makeSHA256Input(byteCount: Int) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: byteCount) { buffer, initializedCount in
            for index in buffer.indices {
                buffer[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 17)
            }
            initializedCount = byteCount
        }
    }

    #endif

    private static func decodeHex(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(hex.utf8.count / 2)
        var highNibble: UInt8?

        for character in hex.utf8 {
            let nibble: UInt8
            switch character {
            case 48...57:
                nibble = character - 48
            case 65...70:
                nibble = character - 55
            case 97...102:
                nibble = character - 87
            default:
                preconditionFailure("Invalid hexadecimal validation vector")
            }

            if let high = highNibble {
                result.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }

        precondition(highNibble == nil)
        return result
    }

    #if SWIFT_CRYPTO_PURE_SWIFT
    private static func validatePureSwiftNISTVerification() {
        let p384PublicKey = decodeHex(
            "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A"
                + "385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292"
                + "DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C9"
                + "0EA0E5F"
        )
        let p384Signature = decodeHex(
            "657A108BD5709DAD00F6FDD003137020A72F916199CE3F488A0C1154EC9F989"
                + "6D716232B4980EE345D13F17635BB1C9003AEB5FD9BE3D8F0BFFA1331F490F2"
                + "F82CD4335CABD5ABD764D7EC991477E59AE6EDA6475AD5E9C58732E06EB7CA6"
                + "871"
        )
        let p384Key = try! P384.Signing.PublicKey(x963Representation: p384PublicKey)
        let p384SignatureValue = try! P384.Signing.ECDSASignature(rawRepresentation: p384Signature)
        let p384Digest = SHA384.hash(data: Array("abc".utf8))
        precondition(p384Key.isValidSignature(p384SignatureValue, for: p384Digest))
        var p384Mutated = p384Signature
        p384Mutated[0] ^= 1
        let p384MutatedSignature = try! P384.Signing.ECDSASignature(rawRepresentation: p384Mutated)
        precondition(!p384Key.isValidSignature(p384MutatedSignature, for: p384Digest))

        let p521PublicKey = decodeHex(
            "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B"
                + "4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31"
                + "C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817"
                + "AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C2408"
                + "8BE94769FD16650"
        )
        let p521Signature = decodeHex(
            "00EF935737F1391BDC574E11C9D1769D3454E8A1611299843931BA10D213CF2"
                + "4FEE3EC80C6B3AF5C1E9A173775BB57CC52F5AD659A2D670D40E113D7E95E5"
                + "C97D78100C3DA0810F3AF0A3D2DF980C22F7F46E451F4DDCE7557871ACCC9B"
                + "EEB36A10C26BAF3DBE393ACFCEDDA5EDAAB9812DA9F2E05B6A174A4FDBD2FE"
                + "D52ECFFE1503BEF"
        )
        let p521Key = try! P521.Signing.PublicKey(x963Representation: p521PublicKey)
        let p521SignatureValue = try! P521.Signing.ECDSASignature(rawRepresentation: p521Signature)
        let p521Digest = SHA512.hash(data: Array("abc".utf8))
        precondition(p521Key.isValidSignature(p521SignatureValue, for: p521Digest))
        var p521Mutated = p521Signature
        p521Mutated[p521Mutated.count - 1] ^= 1
        let p521MutatedSignature = try! P521.Signing.ECDSASignature(rawRepresentation: p521Mutated)
        precondition(!p521Key.isValidSignature(p521MutatedSignature, for: p521Digest))
    }
    #endif
}
