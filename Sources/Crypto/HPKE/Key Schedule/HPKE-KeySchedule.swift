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
@_exported import CryptoKit
#else


extension HPKE {
    internal struct KeySchedule: Sendable {
        fileprivate static let pksIDHashLabel = Data("psk_id_hash".utf8)
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
            
            let pskIDHash = NonSecretOutputLabeledExtract(salt: nil,
                                                          label: HPKE.KeySchedule.pksIDHashLabel,
                                                          ikm: pskID,
                                                          suiteID: ciphersuite.identifier,
                                                          kdf: ciphersuite.kdf)
            
            let infoHash = NonSecretOutputLabeledExtract(salt: nil,
                                                         label: HPKE.KeySchedule.infoHashLabel,
                                                         ikm: info,
                                                         suiteID: ciphersuite.identifier,
                                                         kdf: ciphersuite.kdf)
            
            var keyScheduleContext = Data()
            keyScheduleContext.append(mode.value)
            keyScheduleContext.append(pskIDHash)
            keyScheduleContext.append(infoHash)
            
            let secret = LabeledExtract(salt: Data(unsafeFromContiguousBytes: sharedSecret),
                                        label: HPKE.KeySchedule.secretLabel,
                                        ikm: psk.map { Data(unsafeFromContiguousBytes: $0) },
                                        suiteID: ciphersuite.identifier,
                                        kdf: ciphersuite.kdf)
            
            if !ciphersuite.aead.isExportOnly {
                self.key = LabeledExpand(prk: secret,
                                         label: HPKE.KeySchedule.keyLabel,
                                         info: keyScheduleContext,
                                         outputByteCount: UInt16(ciphersuite.aead.keyByteCount),
                                         suiteID: ciphersuite.identifier,
                                         kdf: ciphersuite.kdf)
                
                self.nonce = NonSecretOutputLabeledExpand(prk: secret,
                                                          label: HPKE.KeySchedule.baseLabel,
                                                          info: keyScheduleContext,
                                                          outputByteCount: UInt16(ciphersuite.aead.nonceByteCount),
                                                          suiteID: ciphersuite.identifier,
                                                          kdf: ciphersuite.kdf)
            }
            
            self.exporterSecret = LabeledExpand(prk: secret,
                                                label: HPKE.KeySchedule.exporterLabel,
                                                info: keyScheduleContext,
                                                outputByteCount: UInt16(ciphersuite.kdf.Nh),
                                                suiteID: ciphersuite.identifier,
                                                kdf: ciphersuite.kdf)
            
            
            self.ciphersuite = ciphersuite
        }
        
        var maxSequenceNumber: UInt64 {
            get {
                let nonceBitCount = UInt64(self.ciphersuite.aead.nonceByteCount * 8)
                if (nonceBitCount >= 64) {
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
            
            let ct = try ciphersuite.aead.seal(msg, authenticating: aad, nonce: currentNonce, using: self.key!)
            try incrementSequenceNumber()
            return ct
        }
        
        mutating func open<C: DataProtocol, AD: DataProtocol>(_ ciphertext: C, authenticating aad: AD) throws(CryptoKitMetaError) -> Data {
            guard !self.ciphersuite.aead.isExportOnly else {
                throw error(HPKE.Errors.exportOnlyMode)
            }
            
            let pt = try ciphersuite.aead.open(ciphertext, nonce: currentNonce, authenticating: aad, using: self.key!)
            try incrementSequenceNumber()
            return pt
        }
        
        var currentNonce: Data {
            var nonceData = [UInt8](repeating: 0, count: ciphersuite.aead.nonceByteCount - MemoryLayout.size(ofValue: sequenceNumber))
            var bigEndian = sequenceNumber.bigEndian
            withUnsafeBytes(of: &(bigEndian)) { (bufferPointer) in
                nonceData.append(contentsOf: bufferPointer)
            }
            let nonce = self.nonce!
            precondition(nonce.count == nonceData.count)
            return Data(zip(nonceData, nonce).lazy.map { $0.0 ^ $0.1 })
        }
    }
}

#endif // canImport(CryptoKit)
