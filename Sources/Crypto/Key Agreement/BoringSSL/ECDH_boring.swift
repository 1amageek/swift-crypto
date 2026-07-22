//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(CryptoKit)
import CryptoKit
#else
internal import CCryptoBoringSSL
import CryptoBoringWrapper

extension P256.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P256.KeyAgreement.PublicKey
    ) throws(CryptoBoringWrapperError) -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

extension P384.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P384.KeyAgreement.PublicKey
    ) throws(CryptoBoringWrapperError) -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

extension P521.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P521.KeyAgreement.PublicKey
    ) throws(CryptoBoringWrapperError) -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}
#endif  // canImport(CryptoKit)
