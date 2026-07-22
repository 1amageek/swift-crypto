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
    static func main() {
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
        #if !canImport(CryptoKit)
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
    }

    private static func decodeHex(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(hex.utf8.count / 2)
        var highNibble: UInt8?

        for character in hex.utf8 {
            let nibble: UInt8
            switch character {
            case 48...57:
                nibble = character - 48
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
}
