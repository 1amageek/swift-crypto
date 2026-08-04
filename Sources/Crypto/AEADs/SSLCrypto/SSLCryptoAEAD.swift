//===----------------------------------------------------------------------===//
//
// Pure Swift AEAD backend for the CryptoKit-compatible facade.
//
// The facade owns the CryptoKit-shaped `Data` result. SSLCrypto owns the
// authenticated encryption state and borrows all input spans. The only
// materialization is at the public sealed-box boundary or when an API exposes
// separate ciphertext and tag storage.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto

private func withContiguousSSLSpan<C: ContiguousBytes, Result>(
    _ bytes: C,
    _ body: (Span<UInt8>) throws -> Result
) rethrows -> Result {
    try bytes.withUnsafeBytes { rawBytes in
        let typedBytes = rawBytes.bindMemory(to: UInt8.self)
        return try body(Span(_unsafeElements: typedBytes))
    }
}

private func withDataProtocolSSLSpan<D: DataProtocol, Result>(
    _ bytes: D,
    _ body: (Span<UInt8>) throws -> Result
) rethrows -> Result {
    if bytes.regions.count == 1, let region = bytes.regions.first {
        return try withContiguousSSLSpan(region, body)
    }

    // Segmented DataProtocol values are normalized once at the facade
    // boundary. The SSLCrypto primitive itself remains borrow-based.
    var contiguous = Data()
    contiguous.reserveCapacity(bytes.count)
    for region in bytes.regions {
        region.withUnsafeBytes { rawBytes in
            contiguous.append(contentsOf: rawBytes)
        }
    }
    return try withContiguousSSLSpan(contiguous, body)
}

private func mapSSLCryptoAEADError(_ error: AEADError) -> CryptoKitMetaError {
    switch error {
    case .invalidKeyLength:
        return CryptoKitError.incorrectKeySize
    case .invalidNonceLength, .outputTooSmall, .messageLimitReached:
        return CryptoKitError.incorrectParameterSize
    case .authenticationFailed:
        return CryptoKitError.authenticationFailure
    case .overlappingInputAndOutput:
        return CryptoKitError.invalidParameter
    }
}

private func copySSLSpan(_ source: Span<UInt8>, into destination: UnsafeMutableRawBufferPointer) {
    guard source.count > 0 else { return }
    source.withUnsafeBytes { sourceBytes in
        guard let sourceBase = sourceBytes.baseAddress, let destinationBase = destination.baseAddress else {
            preconditionFailure("A non-empty span must have a base address")
        }
        destinationBase.copyMemory(from: sourceBase, byteCount: source.count)
    }
}

private func copySSLSpan(_ source: Span<UInt8>, into destination: inout MutableRawSpan) {
    var index = 0
    while index < source.count {
        destination[index] = source[index]
        index += 1
    }
}

private func copySSLSpan(_ source: Span<UInt8>, into destination: inout OutputRawSpan) {
    var index = 0
    while index < source.count {
        destination.append(source[index])
        index += 1
    }
}

enum OpenSSLAESGCMImpl {
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        message: Plaintext,
        nonce: AES.GCM.Nonce?,
        authenticatedData: AuthenticatedData? = nil
    ) throws(CryptoKitMetaError) -> AES.GCM.SealedBox {
        let nonce = nonce ?? AES.GCM.Nonce()
        guard nonce.count == SSLCrypto.AESGCM.nonceByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }
        do {
            return try key.withUnsafeBytes { keyBytes in
                return try withDataProtocolSSLSpan(message) { messageSpan in
                    try withContiguousSSLSpan(nonce) { nonceSpan in
                        if let authenticatedData {
                            return try withDataProtocolSSLSpan(authenticatedData) { dataSpan in
                                var payload = Data(repeating: 0, count: messageSpan.count + SSLCrypto.AESGCM.tagByteCount)
                                do {
                                    try payload.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                                        var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                                        try SSLCrypto.AESGCM.seal(
                                            key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                            plaintext: messageSpan,
                                            authenticatedData: dataSpan,
                                            nonce: nonceSpan,
                                            into: &output
                                        )
                                    }
                                } catch let error as AEADError {
                                    throw mapSSLCryptoAEADError(error)
                                }
                                var combined = Data(nonce)
                                combined.append(payload)
                                return AES.GCM.SealedBox(combined: combined, nonceByteCount: nonce.count)
                            }
                        }
                        let empty = Data()
                        return try withDataProtocolSSLSpan(empty) { dataSpan in
                            var payload = Data(repeating: 0, count: messageSpan.count + SSLCrypto.AESGCM.tagByteCount)
                            do {
                                try payload.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                                    var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                                    try SSLCrypto.AESGCM.seal(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        plaintext: messageSpan,
                                        authenticatedData: dataSpan,
                                        nonce: nonceSpan,
                                        into: &output
                                    )
                                }
                            } catch let error as AEADError {
                                throw mapSSLCryptoAEADError(error)
                            }
                            var combined = Data(nonce)
                            combined.append(payload)
                            return AES.GCM.SealedBox(combined: combined, nonceByteCount: nonce.count)
                        }
                    }
                }
            }
        } catch {
            throw error
        }
    }

    static func seal(
        key: SymmetricKey,
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        guard nonce.byteCount == SSLCrypto.AESGCM.nonceByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }
        var combined = Data(repeating: 0, count: message.byteCount + SSLCrypto.AESGCM.tagByteCount)
        do {
            try key.withUnsafeBytes { keyBytes in
                try nonce.withUnsafeBytes { nonceBytes in
                    let nonceSpan = Span(_unsafeElements: nonceBytes.bindMemory(to: UInt8.self))
                    try combined.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                        var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                        try message.withUnsafeBytes { messageBytes in
                            let messageSpan = Span(_unsafeElements: messageBytes.bindMemory(to: UInt8.self))
                            if let authenticatedData {
                                try authenticatedData.withUnsafeBytes { dataBytes in
                                    try SSLCrypto.AESGCM.seal(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        plaintext: messageSpan,
                                        authenticatedData: Span(_unsafeElements: dataBytes.bindMemory(to: UInt8.self)),
                                        nonce: nonceSpan,
                                        into: &output
                                    )
                                }
                            } else {
                                try SSLCrypto.AESGCM.seal(
                                    key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                    plaintext: messageSpan,
                                    authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
                                    nonce: nonceSpan,
                                    into: &output
                                )
                            }
                        }
                    }
                }
            }
        } catch let error as AEADError {
            throw mapSSLCryptoAEADError(error)
        }
        let messageByteCount = message.byteCount
        combined.withUnsafeBytes { rawBytes in
            let bytes = rawBytes.bindMemory(to: UInt8.self)
            let ciphertextBytes = Span(_unsafeElements: UnsafeBufferPointer(start: bytes.baseAddress, count: messageByteCount))
            copySSLSpan(ciphertextBytes, into: &message)
            let tagBytes = Span(_unsafeElements: UnsafeBufferPointer(start: bytes.baseAddress!.advanced(by: messageByteCount), count: SSLCrypto.AESGCM.tagByteCount))
            copySSLSpan(tagBytes, into: &tag)
        }
    }

    static func open<AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        sealedBox: AES.GCM.SealedBox,
        authenticatedData: AuthenticatedData? = nil
    ) throws(CryptoKitMetaError) -> Data {
        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag
        var ciphertextAndTag = Data(ciphertext)
        ciphertextAndTag.append(tag)
        do {
            return try key.withUnsafeBytes { keyBytes in
                func open(_ authenticatedDataSpan: Span<UInt8>, ciphertextSpan: Span<UInt8>, nonceSpan: Span<UInt8>) throws(CryptoKitMetaError) -> Data {
                    var output = Data(repeating: 0, count: ciphertext.count)
                    do {
                        try output.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                            var destination = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                            try SSLCrypto.AESGCM.open(
                                key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                ciphertextAndTag: ciphertextSpan,
                                authenticatedData: authenticatedDataSpan,
                                nonce: nonceSpan,
                                into: &destination
                            )
                        }
                    } catch let error as AEADError {
                        throw mapSSLCryptoAEADError(error)
                    }
                    return output
                }

                return try withDataProtocolSSLSpan(ciphertextAndTag) { ciphertextSpan in
                    try withContiguousSSLSpan(sealedBox.nonce) { nonceSpan in
                        if let authenticatedData {
                            return try withDataProtocolSSLSpan(authenticatedData) { dataSpan in
                                try open(dataSpan, ciphertextSpan: ciphertextSpan, nonceSpan: nonceSpan)
                            }
                        }
                        let empty = Data()
                        return try withDataProtocolSSLSpan(empty) { dataSpan in
                            try open(dataSpan, ciphertextSpan: ciphertextSpan, nonceSpan: nonceSpan)
                        }
                    }
                }
            }
        } catch {
            throw error
        }
    }

    static func open(
        key: SymmetricKey,
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: RawSpan
    ) throws(CryptoKitMetaError) {
        guard nonce.byteCount == SSLCrypto.AESGCM.nonceByteCount, tag.byteCount == SSLCrypto.AESGCM.tagByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }
        var ciphertextAndTag = Data(repeating: 0, count: message.byteCount + tag.byteCount)
        message.withUnsafeBytes { messageBytes in
            ciphertextAndTag.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                output.copyMemory(from: messageBytes)
            }
        }
        tag.withUnsafeBytes { tagBytes in
            ciphertextAndTag.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                guard let source = tagBytes.baseAddress, let destination = output.baseAddress else { return }
                destination.advanced(by: message.byteCount).copyMemory(from: source, byteCount: tag.byteCount)
            }
        }
        var plaintext = Data(repeating: 0, count: message.byteCount)
        do {
            try key.withUnsafeBytes { keyBytes in
                try nonce.withUnsafeBytes { nonceBytes in
                    let nonceSpan = Span(_unsafeElements: nonceBytes.bindMemory(to: UInt8.self))
                    try ciphertextAndTag.withUnsafeBytes { ciphertextBytes in
                        let ciphertextSpan = Span(_unsafeElements: ciphertextBytes.bindMemory(to: UInt8.self))
                        try plaintext.withUnsafeMutableBytes { (outputBytes: UnsafeMutableRawBufferPointer) in
                            var destination = MutableSpan(_unsafeElements: outputBytes.bindMemory(to: UInt8.self))
                            if let authenticatedData {
                                try authenticatedData.withUnsafeBytes { dataBytes in
                                    try SSLCrypto.AESGCM.open(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        ciphertextAndTag: ciphertextSpan,
                                        authenticatedData: Span(_unsafeElements: dataBytes.bindMemory(to: UInt8.self)),
                                        nonce: nonceSpan,
                                        into: &destination
                                    )
                                }
                            } else {
                                try SSLCrypto.AESGCM.open(
                                    key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                    ciphertextAndTag: ciphertextSpan,
                                    authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
                                    nonce: nonceSpan,
                                    into: &destination
                                )
                            }
                        }
                    }
                }
            }
        } catch let error as AEADError {
            throw mapSSLCryptoAEADError(error)
        }
        plaintext.withUnsafeBytes { plaintextBytes in
            let plaintextSpan = Span(_unsafeElements: plaintextBytes.bindMemory(to: UInt8.self))
            copySSLSpan(plaintextSpan, into: &message)
        }
    }
}

enum OpenSSLChaChaPolyImpl {
    static func encrypt<M: DataProtocol, AD: DataProtocol>(
        key: SymmetricKey,
        message: M,
        nonce: ChaChaPoly.Nonce?,
        authenticatedData: AD?
    ) throws(CryptoKitMetaError) -> ChaChaPoly.SealedBox {
        let nonce = nonce ?? ChaChaPoly.Nonce()
        do {
            return try key.withUnsafeBytes { keyBytes in
                return try withDataProtocolSSLSpan(message) { messageSpan in
                    try withContiguousSSLSpan(nonce) { nonceSpan in
                        if let authenticatedData {
                            return try withDataProtocolSSLSpan(authenticatedData) { dataSpan in
                                var payload = Data(repeating: 0, count: messageSpan.count + SSLCrypto.ChaCha20Poly1305.tagByteCount)
                                do {
                                    try payload.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                                        var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                                        try SSLCrypto.ChaCha20Poly1305.seal(
                                            key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                            plaintext: messageSpan,
                                            authenticatedData: dataSpan,
                                            nonce: nonceSpan,
                                            into: &output
                                        )
                                    }
                                } catch let error as AEADError {
                                    throw mapSSLCryptoAEADError(error)
                                }
                                var combined = Data(nonce)
                                combined.append(payload)
                                return ChaChaPoly.SealedBox(combined: combined, nonceByteCount: nonce.count)
                            }
                        }
                        let empty = Data()
                        return try withDataProtocolSSLSpan(empty) { dataSpan in
                            var payload = Data(repeating: 0, count: messageSpan.count + SSLCrypto.ChaCha20Poly1305.tagByteCount)
                            do {
                                try payload.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                                    var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                                    try SSLCrypto.ChaCha20Poly1305.seal(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        plaintext: messageSpan,
                                        authenticatedData: dataSpan,
                                        nonce: nonceSpan,
                                        into: &output
                                    )
                                }
                            } catch let error as AEADError {
                                throw mapSSLCryptoAEADError(error)
                            }
                            var combined = Data(nonce)
                            combined.append(payload)
                            return ChaChaPoly.SealedBox(combined: combined, nonceByteCount: nonce.count)
                        }
                    }
                }
            }
        } catch {
            throw error
        }
    }

    static func encrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        var combined = Data(repeating: 0, count: message.byteCount + SSLCrypto.ChaCha20Poly1305.tagByteCount)
        do {
            try key.withUnsafeBytes { keyBytes in
                try nonce.withUnsafeBytes { nonceBytes in
                    let nonceSpan = Span(_unsafeElements: nonceBytes.bindMemory(to: UInt8.self))
                    try combined.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                        var output = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                        try message.withUnsafeBytes { messageBytes in
                            let messageSpan = Span(_unsafeElements: messageBytes.bindMemory(to: UInt8.self))
                            if let authenticatedData {
                                try authenticatedData.withUnsafeBytes { dataBytes in
                                    try SSLCrypto.ChaCha20Poly1305.seal(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        plaintext: messageSpan,
                                        authenticatedData: Span(_unsafeElements: dataBytes.bindMemory(to: UInt8.self)),
                                        nonce: nonceSpan,
                                        into: &output
                                    )
                                }
                            } else {
                                try SSLCrypto.ChaCha20Poly1305.seal(
                                    key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                    plaintext: messageSpan,
                                    authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
                                    nonce: nonceSpan,
                                    into: &output
                                )
                            }
                        }
                    }
                }
            }
        } catch let error as AEADError {
            throw mapSSLCryptoAEADError(error)
        }
        let messageByteCount = message.byteCount
        combined.withUnsafeBytes { rawBytes in
            let bytes = rawBytes.bindMemory(to: UInt8.self)
            let ciphertext = Span(_unsafeElements: UnsafeBufferPointer(start: bytes.baseAddress, count: messageByteCount))
            copySSLSpan(ciphertext, into: &message)
            let tagBytes = Span(_unsafeElements: UnsafeBufferPointer(start: bytes.baseAddress!.advanced(by: messageByteCount), count: SSLCrypto.ChaCha20Poly1305.tagByteCount))
            copySSLSpan(tagBytes, into: &tag)
        }
    }

    static func decrypt<AD: DataProtocol>(
        key: SymmetricKey,
        ciphertext: ChaChaPoly.SealedBox,
        authenticatedData: AD?
    ) throws(CryptoKitMetaError) -> Data {
        let message = ciphertext.ciphertext
        var ciphertextAndTag = Data(message)
        ciphertextAndTag.append(ciphertext.tag)
        do {
            return try key.withUnsafeBytes { keyBytes in
                func open(_ authenticatedDataSpan: Span<UInt8>, ciphertextSpan: Span<UInt8>, nonceSpan: Span<UInt8>) throws(CryptoKitMetaError) -> Data {
                    var output = Data(repeating: 0, count: message.count)
                    do {
                        try output.withUnsafeMutableBytes { (rawBytes: UnsafeMutableRawBufferPointer) in
                            var destination = MutableSpan(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
                            try SSLCrypto.ChaCha20Poly1305.open(
                                key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                ciphertextAndTag: ciphertextSpan,
                                authenticatedData: authenticatedDataSpan,
                                nonce: nonceSpan,
                                into: &destination
                            )
                        }
                    } catch let error as AEADError {
                        throw mapSSLCryptoAEADError(error)
                    }
                    return output
                }

                return try withDataProtocolSSLSpan(ciphertextAndTag) { ciphertextSpan in
                    try withContiguousSSLSpan(ciphertext.nonce) { nonceSpan in
                        if let authenticatedData {
                            return try withDataProtocolSSLSpan(authenticatedData) { dataSpan in
                                try open(dataSpan, ciphertextSpan: ciphertextSpan, nonceSpan: nonceSpan)
                            }
                        }
                        let empty = Data()
                        return try withDataProtocolSSLSpan(empty) { dataSpan in
                            try open(dataSpan, ciphertextSpan: ciphertextSpan, nonceSpan: nonceSpan)
                        }
                    }
                }
            }
        } catch {
            throw error
        }
    }

    static func decrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan?
    ) throws(CryptoKitMetaError) {
        var ciphertextAndTag = Data(repeating: 0, count: message.byteCount + tag.byteCount)
        message.withUnsafeBytes { messageBytes in
            ciphertextAndTag.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                output.copyMemory(from: messageBytes)
            }
        }
        tag.withUnsafeBytes { tagBytes in
            ciphertextAndTag.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                guard let source = tagBytes.baseAddress, let destination = output.baseAddress else { return }
                destination.advanced(by: message.byteCount).copyMemory(from: source, byteCount: tag.byteCount)
            }
        }
        var plaintext = Data(repeating: 0, count: message.byteCount)
        do {
            try key.withUnsafeBytes { keyBytes in
                try nonce.withUnsafeBytes { nonceBytes in
                    let nonceSpan = Span(_unsafeElements: nonceBytes.bindMemory(to: UInt8.self))
                    try ciphertextAndTag.withUnsafeBytes { ciphertextBytes in
                        let ciphertextSpan = Span(_unsafeElements: ciphertextBytes.bindMemory(to: UInt8.self))
                        try plaintext.withUnsafeMutableBytes { (outputBytes: UnsafeMutableRawBufferPointer) in
                            var destination = MutableSpan(_unsafeElements: outputBytes.bindMemory(to: UInt8.self))
                            if let authenticatedData {
                                try authenticatedData.withUnsafeBytes { dataBytes in
                                    try SSLCrypto.ChaCha20Poly1305.open(
                                        key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                        ciphertextAndTag: ciphertextSpan,
                                        authenticatedData: Span(_unsafeElements: dataBytes.bindMemory(to: UInt8.self)),
                                        nonce: nonceSpan,
                                        into: &destination
                                    )
                                }
                            } else {
                                try SSLCrypto.ChaCha20Poly1305.open(
                                    key: Span(_unsafeElements: keyBytes.bindMemory(to: UInt8.self)),
                                    ciphertextAndTag: ciphertextSpan,
                                    authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
                                    nonce: nonceSpan,
                                    into: &destination
                                )
                            }
                        }
                    }
                }
            }
        } catch let error as AEADError {
            throw mapSSLCryptoAEADError(error)
        }
        plaintext.withUnsafeBytes { plaintextBytes in
            let plaintextSpan = Span(_unsafeElements: plaintextBytes.bindMemory(to: UInt8.self))
            copySSLSpan(plaintextSpan, into: &message)
        }
    }
}

#endif
