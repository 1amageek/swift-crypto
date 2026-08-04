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



private let protocolLabel = Data("HPKE-v1".utf8)
private let eaePRKLabel = Data("eae_prk".utf8)
private let sharedSecretLabel = Data("shared_secret".utf8)

internal func extractAndExpand<SharedSecret: HPKETranscript, KEMContext: HPKETranscript>(
    sharedSecret: SharedSecret,
    kemContext: KEMContext,
    suiteID: Data,
    kem: HPKE.KEM,
    kdf: HPKE.KDF
) -> SymmetricKey {
    return withLabeledExtractedPseudoRandomKey(
        salt: Optional(Data()),
        label: eaePRKLabel,
        transcript: Optional(sharedSecret),
        suiteID: suiteID,
        kdf: kdf
    ) { eaePRK in
        labeledExpand(
            pseudoRandomKey: eaePRK,
            label: sharedSecretLabel,
            transcript: kemContext,
            outputByteCount: kem.nSecret,
            suiteID: suiteID,
            kdf: kdf
        )
    }
}

internal func withLabeledExtractedPseudoRandomKey<
    Salt: ContiguousBytes,
    InputKeyMaterial: ContiguousBytes,
    Result
>(
    salt: Salt?,
    label: Data,
    inputKeyMaterial: InputKeyMaterial?,
    suiteID: Data,
    kdf: HPKE.KDF,
    _ body: (RawSpan) -> Result
) -> Result {
    let transcript = inputKeyMaterial.map { HPKEInputKeyMaterialTranscript(bytes: $0) }
    return withLabeledExtractedPseudoRandomKey(
        salt: salt,
        label: label,
        transcript: transcript,
        suiteID: suiteID,
        kdf: kdf,
        body
    )
}

internal func withLabeledExtractedPseudoRandomKey<
    Salt: ContiguousBytes,
    Transcript: HPKETranscript,
    Result
>(
    salt: Salt?,
    label: Data,
    transcript: Transcript?,
    suiteID: Data,
    kdf: HPKE.KDF,
    _ body: (RawSpan) -> Result
) -> Result {
    switch kdf {
    case .HKDF_SHA256:
        return withLabeledExtractDigest(
            salt: salt,
            label: label,
            transcript: transcript,
            suiteID: suiteID,
            using: SHA256.self,
            body
        )
    case .HKDF_SHA384:
        return withLabeledExtractDigest(
            salt: salt,
            label: label,
            transcript: transcript,
            suiteID: suiteID,
            using: SHA384.self,
            body
        )
    case .HKDF_SHA512:
        return withLabeledExtractDigest(
            salt: salt,
            label: label,
            transcript: transcript,
            suiteID: suiteID,
            using: SHA512.self,
            body
        )
    }
}

internal func labeledExpand<PseudoRandomKey: ContiguousBytes, Info: DataProtocol>(
    pseudoRandomKey: PseudoRandomKey,
    label: Data,
    info: Info,
    outputByteCount: UInt16,
    suiteID: Data,
    kdf: HPKE.KDF
) -> SymmetricKey {
    labeledExpand(
        pseudoRandomKey: pseudoRandomKey,
        label: label,
        transcript: HPKEInformationTranscript(bytes: info),
        outputByteCount: outputByteCount,
        suiteID: suiteID,
        kdf: kdf
    )
}

internal func labeledExpand<PseudoRandomKey: ContiguousBytes, Transcript: HPKETranscript>(
    pseudoRandomKey: PseudoRandomKey,
    label: Data,
    transcript: Transcript,
    outputByteCount: UInt16,
    suiteID: Data,
    kdf: HPKE.KDF
) -> SymmetricKey {
    pseudoRandomKey.withUnsafeBytes { buffer in
        labeledExpand(
            pseudoRandomKey: buffer.bytes,
            label: label,
            transcript: transcript,
            outputByteCount: outputByteCount,
            suiteID: suiteID,
            kdf: kdf
        )
    }
}

internal func labeledExpand<Transcript: HPKETranscript>(
    pseudoRandomKey: RawSpan,
    label: Data,
    transcript: Transcript,
    outputByteCount: UInt16,
    suiteID: Data,
    kdf: HPKE.KDF
) -> SymmetricKey {
    switch kdf {
    case .HKDF_SHA256:
        return labeledExpand(
            pseudoRandomKey: pseudoRandomKey,
            label: label,
            transcript: transcript,
            outputByteCount: outputByteCount,
            suiteID: suiteID,
            using: SHA256.self
        )
    case .HKDF_SHA384:
        return labeledExpand(
            pseudoRandomKey: pseudoRandomKey,
            label: label,
            transcript: transcript,
            outputByteCount: outputByteCount,
            suiteID: suiteID,
            using: SHA384.self
        )
    case .HKDF_SHA512:
        return labeledExpand(
            pseudoRandomKey: pseudoRandomKey,
            label: label,
            transcript: transcript,
            outputByteCount: outputByteCount,
            suiteID: suiteID,
            using: SHA512.self
        )
    }
}

internal func nonSecretOutputLabeledExtract(
    salt: Data?,
    label: Data,
    inputKeyMaterial: Data?,
    suiteID: Data,
    kdf: HPKE.KDF
) -> Data {
    let transcript = inputKeyMaterial.map { HPKEInputKeyMaterialTranscript(bytes: $0) }
    return withLabeledExtractedPseudoRandomKey(
        salt: salt,
        label: label,
        transcript: transcript,
        suiteID: suiteID,
        kdf: kdf
    ) { pseudoRandomKey in
        pseudoRandomKey.withUnsafeBytes { Data($0) }
    }
}

internal func nonSecretOutputLabeledExpand<
    PseudoRandomKey: ContiguousBytes,
    Transcript: HPKETranscript
>(
    pseudoRandomKey: PseudoRandomKey,
    label: Data,
    transcript: Transcript,
    outputByteCount: UInt16,
    suiteID: Data,
    kdf: HPKE.KDF
) -> Data {
    let key = labeledExpand(
        pseudoRandomKey: pseudoRandomKey,
        label: label,
        transcript: transcript,
        outputByteCount: outputByteCount,
        suiteID: suiteID,
        kdf: kdf
    )
    return key.withUnsafeBytes { Data($0) }
}

internal func nonSecretOutputLabeledExpand<Transcript: HPKETranscript>(
    pseudoRandomKey: RawSpan,
    label: Data,
    transcript: Transcript,
    outputByteCount: UInt16,
    suiteID: Data,
    kdf: HPKE.KDF
) -> Data {
    let key = labeledExpand(
        pseudoRandomKey: pseudoRandomKey,
        label: label,
        transcript: transcript,
        outputByteCount: outputByteCount,
        suiteID: suiteID,
        kdf: kdf
    )
    return key.withUnsafeBytes { Data($0) }
}

private func withLabeledExtractDigest<
    H: HashFunction,
    Salt: ContiguousBytes,
    Transcript: HPKETranscript,
    Result
>(
    salt: Salt?,
    label: Data,
    transcript: Transcript?,
    suiteID: Data,
    using _: H.Type,
    _ body: (RawSpan) -> Result
) -> Result {
    func updateInputKeyMaterial(_ authenticator: inout HMAC<H>) {
        authenticator.update(data: protocolLabel)
        authenticator.update(data: suiteID)
        authenticator.update(data: label)
        if let transcript {
            transcript.forEachByteRegion { bytes in
                authenticator.update(bytes: bytes)
            }
        }
    }

    func withSalt(_ salt: RawSpan?) -> Result {
        HKDF<H>.withExtractedKeyBytes(
            salt: salt,
            updateInputKeyMaterial: updateInputKeyMaterial
        ) { buffer in
            body(buffer.bytes)
        }
    }

    if let salt {
        return salt.withUnsafeBytes { buffer in
            withSalt(buffer.bytes)
        }
    }
    return withSalt(nil)
}

private func labeledExpand<
    H: HashFunction,
    Transcript: HPKETranscript
>(
    pseudoRandomKey: RawSpan,
    label: Data,
    transcript: Transcript,
    outputByteCount: UInt16,
    suiteID: Data,
    using _: H.Type
) -> SymmetricKey {
    SymmetricKey(capacity: Int(outputByteCount)) { output in
        HKDF<H>.expandValidated(
            pseudoRandomKey: pseudoRandomKey,
            into: &output,
            updateInfo: { authenticator in
                var encodedOutputByteCount = outputByteCount.bigEndian
                withUnsafeBytes(of: &encodedOutputByteCount) { buffer in
                    authenticator.update(bufferPointer: buffer)
                }
                authenticator.update(data: protocolLabel)
                authenticator.update(data: suiteID)
                authenticator.update(data: label)
                transcript.forEachByteRegion { bytes in
                    authenticator.update(bytes: bytes)
                }
            }
        )
    }
}

#endif // canImport(CryptoKit)
