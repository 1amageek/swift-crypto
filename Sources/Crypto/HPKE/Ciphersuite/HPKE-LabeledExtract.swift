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



private let protocolLabel = Data("HPKE-v1".utf8)
private let eaePRKLabel = Data("eae_prk".utf8)
private let sharedSecretLabel = Data("shared_secret".utf8)

extension Data {
    internal init<CB: ContiguousBytes>(unsafeFromContiguousBytes cb: CB) {
        self = cb.withUnsafeBytes { return Data($0) }
    }
}

internal func ExtractAndExpand<ZZ: ContiguousBytes>(zz: ZZ, kemContext: Data, suiteID: Data, kem: HPKE.KEM, kdf: HPKE.KDF) -> SymmetricKey {
    let eaePrk = LabeledExtract(salt: Data(), label: eaePRKLabel, ikm: Data(unsafeFromContiguousBytes: zz), suiteID: suiteID, kdf: kdf)
    
    return LabeledExpand(prk: eaePrk, label: sharedSecretLabel,
                         info: kemContext, outputByteCount: kem.nSecret, suiteID: suiteID, kdf: kdf)
}

internal func LabeledExtract(salt: Data?, label: Data, ikm: Data?, suiteID: Data, kdf: HPKE.KDF) -> SymmetricKey {
    var labeled_ikm = protocolLabel
    labeled_ikm.append(suiteID)
    labeled_ikm.append(label)
    ikm.map { labeled_ikm.append($0) }
    return kdf.extract(salt: salt ?? Data(), ikm: SymmetricKey(data: labeled_ikm))
}

internal func LabeledExpand<Info: DataProtocol>(prk: SymmetricKey, label: Data, info: Info, outputByteCount: UInt16, suiteID: Data, kdf: HPKE.KDF) -> SymmetricKey {
    var labeled_info = I2OSP(value: Int(outputByteCount), outputByteCount: 2)
    labeled_info.append(protocolLabel)
    labeled_info.append(suiteID)
    labeled_info.append(label)
    labeled_info.append(contentsOf: info)
    return kdf.expand(prk: prk, info: labeled_info, outputByteCount: Int(outputByteCount))
}

internal func NonSecretOutputLabeledExtract(salt: Data?, label: Data, ikm: Data?, suiteID: Data, kdf: HPKE.KDF) -> Data {
    return Data(unsafeFromContiguousBytes: LabeledExtract(salt: salt, label: label, ikm: ikm, suiteID: suiteID, kdf: kdf))
}

internal func NonSecretOutputLabeledExpand(prk: SymmetricKey, label: Data, info: Data, outputByteCount: UInt16, suiteID: Data, kdf: HPKE.KDF) -> Data {
    return Data(unsafeFromContiguousBytes: LabeledExpand(prk: prk, label: label, info: info, outputByteCount: outputByteCount, suiteID: suiteID, kdf: kdf))
}

#endif // canImport(CryptoKit)
