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


extension HPKE {
    internal struct KeySchedule: Sendable {
        fileprivate static let presharedKeyIdentifierHashLabel = Data("psk_id_hash".utf8)
        fileprivate static let infoHashLabel = Data("info_hash".utf8)
        fileprivate static let secretLabel = Data("secret".utf8)
        fileprivate static let keyLabel = Data("key".utf8)
        fileprivate static let baseLabel = Data("base_nonce".utf8)
        fileprivate static let exporterLabel = Data("exp".utf8)
        
        var sequenceNumber: UInt64 = 0
        var key: SymmetricKey?
        var nonce: Data?
        var exporterSecret: SymmetricKey
        var ciphersuite: HPKE.Ciphersuite
        
        static func verifyPSKInputs(mode: HPKE.Mode, psk: SymmetricKey?, pskID: Data?) throws(CryptoKitMetaError) {
            let gotPSK = (psk != nil)
            let gotPSKID = (pskID != nil)
            
            if gotPSK != gotPSKID {
                throw error(HPKE.Errors.inconsistentPSKInputs)
            }
            
            if gotPSK && !HPKE.Mode.pskModes.contains(mode) {
                throw error(HPKE.Errors.unexpectedPSK)
            }
            
            if !gotPSK && HPKE.Mode.pskModes.contains(mode) {
                throw error(HPKE.Errors.expectedPSK)
            }
        }
        
        init<SharedSecretBytes: ContiguousBytes>(mode: HPKE.Mode, sharedSecret: SharedSecretBytes, info: Data, psk: SymmetricKey?, pskID: Data?, ciphersuite: Ciphersuite) throws(CryptoKitMetaError) {
            try HPKE.KeySchedule.verifyPSKInputs(mode: mode, psk: psk, pskID: pskID)
            
            let pskIDHash = nonSecretOutputLabeledExtract(
                salt: nil,
                label: HPKE.KeySchedule.presharedKeyIdentifierHashLabel,
                inputKeyMaterial: pskID,
                suiteID: ciphersuite.identifier,
                kdf: ciphersuite.kdf
            )
            
            let infoHash = nonSecretOutputLabeledExtract(
                salt: nil,
                label: HPKE.KeySchedule.infoHashLabel,
                inputKeyMaterial: info,
                suiteID: ciphersuite.identifier,
                kdf: ciphersuite.kdf
            )

            let keyScheduleTranscript = HPKEKeyScheduleTranscript(
                mode: mode.value,
                presharedKeyIdentifierHash: pskIDHash,
                infoHash: infoHash
            )

            let derivedValues = withLabeledExtractedPseudoRandomKey(
                salt: Optional(sharedSecret),
                label: HPKE.KeySchedule.secretLabel,
                inputKeyMaterial: psk,
                suiteID: ciphersuite.identifier,
                kdf: ciphersuite.kdf
            ) { secret in
                let key: SymmetricKey?
                let nonce: Data?
                if ciphersuite.aead.isExportOnly {
                    key = nil
                    nonce = nil
                } else {
                    key = labeledExpand(
                        pseudoRandomKey: secret,
                        label: HPKE.KeySchedule.keyLabel,
                        transcript: keyScheduleTranscript,
                        outputByteCount: UInt16(ciphersuite.aead.keyByteCount),
                        suiteID: ciphersuite.identifier,
                        kdf: ciphersuite.kdf
                    )

                    nonce = nonSecretOutputLabeledExpand(
                        pseudoRandomKey: secret,
                        label: HPKE.KeySchedule.baseLabel,
                        transcript: keyScheduleTranscript,
                        outputByteCount: UInt16(ciphersuite.aead.nonceByteCount),
                        suiteID: ciphersuite.identifier,
                        kdf: ciphersuite.kdf
                    )
                }

                let exporterSecret = labeledExpand(
                    pseudoRandomKey: secret,
                    label: HPKE.KeySchedule.exporterLabel,
                    transcript: keyScheduleTranscript,
                    outputByteCount: UInt16(ciphersuite.kdf.Nh),
                    suiteID: ciphersuite.identifier,
                    kdf: ciphersuite.kdf
                )

                return (
                    key: key,
                    nonce: nonce,
                    exporterSecret: exporterSecret
                )
            }

            self.key = derivedValues.key
            self.nonce = derivedValues.nonce
            self.exporterSecret = derivedValues.exporterSecret
            self.ciphersuite = ciphersuite
        }
        
        var maxSequenceNumber: UInt64 {
            get {
                let nonceBitCount = UInt64(self.ciphersuite.aead.nonceByteCount * 8)
                if nonceBitCount >= 64 {
                    return UInt64.max
                }
                
                return ((UInt64(1) << nonceBitCount) - 1)
            }
        }
        
        mutating func incrementSequenceNumber() throws(CryptoKitMetaError) {
            if self.sequenceNumber >= maxSequenceNumber {
                throw error(HPKE.Errors.outOfRangeSequenceNumber)
            }
            sequenceNumber += 1
        }
        
        mutating func seal<M: DataProtocol, AD: DataProtocol>(_ msg: M, authenticating aad: AD) throws(CryptoKitMetaError) -> Data {
            guard !self.ciphersuite.aead.isExportOnly else {
                throw error(HPKE.Errors.exportOnlyMode)
            }
            guard let key else {
                preconditionFailure("HPKE key schedule is missing its encryption key")
            }

            let ct = try ciphersuite.aead.seal(msg, authenticating: aad, nonce: currentNonce, using: key)
            try incrementSequenceNumber()
            return ct
        }
        
        mutating func open<C: DataProtocol, AD: DataProtocol>(_ ciphertext: C, authenticating aad: AD) throws(CryptoKitMetaError) -> Data {
            guard !self.ciphersuite.aead.isExportOnly else {
                throw error(HPKE.Errors.exportOnlyMode)
            }
            guard let key else {
                preconditionFailure("HPKE key schedule is missing its encryption key")
            }

            let pt = try ciphersuite.aead.open(ciphertext, nonce: currentNonce, authenticating: aad, using: key)
            try incrementSequenceNumber()
            return pt
        }
        
        var currentNonce: Data {
            guard let nonce else {
                preconditionFailure("HPKE key schedule is missing its base nonce")
            }
            guard sequenceNumber != 0 else {
                return nonce
            }
            precondition(nonce.count >= MemoryLayout<UInt64>.size)

            var currentNonce = nonce
            var encodedSequenceNumber = sequenceNumber.bigEndian
            currentNonce.withUnsafeMutableBytes { nonceBytes in
                withUnsafeBytes(of: &encodedSequenceNumber) { sequenceBytes in
                    let sequenceOffset = nonceBytes.count - sequenceBytes.count
                    for index in sequenceBytes.indices {
                        nonceBytes[sequenceOffset + index] ^= sequenceBytes[index]
                    }
                }
            }
            return currentNonce
        }
    }
}

#endif // canImport(CryptoKit)
