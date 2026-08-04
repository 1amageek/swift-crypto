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


#if canImport(CryptoKit) && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else



private let kemSuiteLabel = Data("KEM".utf8)

extension HPKE {
    struct KeyExchangeDerivation {
        static func extractAndExpand<SharedSecret: ContiguousBytes>(
            sharedSecret: SharedSecret,
            encapsulatedKey: Data,
            recipientPublicKey: Data,
            kem: HPKE.KEM,
            kdf: HPKE.KDF
        ) -> SymmetricKey {
            let secretTranscript = HPKEInputKeyMaterialTranscript(bytes: sharedSecret)
            let contextTranscript = HPKEKEMContextTranscript(
                encapsulatedKey: encapsulatedKey,
                recipientPublicKey: recipientPublicKey,
                senderPublicKey: nil
            )
            var suiteID = kemSuiteLabel
            suiteID.append(kem.identifier)
            return Crypto.extractAndExpand(
                sharedSecret: secretTranscript,
                kemContext: contextTranscript,
                suiteID: suiteID,
                kem: kem,
                kdf: kdf
            )
        }

        static func extractAndExpand<
            EphemeralSharedSecret: ContiguousBytes,
            AuthenticationSharedSecret: ContiguousBytes
        >(
            ephemeralSharedSecret: EphemeralSharedSecret,
            authenticationSharedSecret: AuthenticationSharedSecret,
            encapsulatedKey: Data,
            recipientPublicKey: Data,
            senderPublicKey: Data,
            kem: HPKE.KEM,
            kdf: HPKE.KDF
        ) -> SymmetricKey {
            let secretTranscript = HPKEAuthenticatedSharedSecretTranscript(
                ephemeralSharedSecret: ephemeralSharedSecret,
                authenticationSharedSecret: authenticationSharedSecret
            )
            let contextTranscript = HPKEKEMContextTranscript(
                encapsulatedKey: encapsulatedKey,
                recipientPublicKey: recipientPublicKey,
                senderPublicKey: senderPublicKey
            )
            var suiteID = kemSuiteLabel
            suiteID.append(kem.identifier)
            return Crypto.extractAndExpand(
                sharedSecret: secretTranscript,
                kemContext: contextTranscript,
                suiteID: suiteID,
                kem: kem,
                kdf: kdf
            )
        }
    }
}

#endif // canImport(CryptoKit)
