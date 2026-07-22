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

#if hasFeature(Embedded) && !canImport(CryptoKit)
/// A static digest discriminator for environments without runtime type metadata.
public enum _DigestAlgorithm: Sendable {
    case sha1
    case sha256
    case sha384
    case sha512
    case unsupported
}

extension SHA256Digest {
    public static var _algorithm: _DigestAlgorithm { .sha256 }
}

extension SHA384Digest {
    public static var _algorithm: _DigestAlgorithm { .sha384 }
}

extension SHA512Digest {
    public static var _algorithm: _DigestAlgorithm { .sha512 }
}

extension Insecure.SHA1Digest {
    public static var _algorithm: _DigestAlgorithm { .sha1 }
}

extension Insecure.MD5Digest {
    public static var _algorithm: _DigestAlgorithm { .unsupported }
}

extension SHA3_256Digest {
    public static var _algorithm: _DigestAlgorithm { .unsupported }
}

extension SHA3_384Digest {
    public static var _algorithm: _DigestAlgorithm { .unsupported }
}

extension SHA3_512Digest {
    public static var _algorithm: _DigestAlgorithm { .unsupported }
}
#endif
