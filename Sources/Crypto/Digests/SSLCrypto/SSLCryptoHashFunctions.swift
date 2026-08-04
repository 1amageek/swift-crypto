//===----------------------------------------------------------------------===//
//
// Pure Swift SHA-384 and SHA-512 adapters.
//
// The CryptoKit-compatible value types keep their copy-on-write API. The
// mutable SSLCrypto context is owned behind `Synchronization.Mutex`, so the
// same storage and synchronization contract applies to Native, WASM, and
// Embedded targets. Finalization clones the context and never mutates the
// caller-visible state.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto
import Synchronization

private final class SSLCryptoSHA256Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA256Context>

    init() {
        state = Mutex(SSLCrypto.SHA256Context())
    }

    init(_ context: consuming SSLCrypto.SHA256Context) {
        state = Mutex(consume context)
    }

    func copy() -> SSLCryptoSHA256Box {
        state.withLock { context in
            SSLCryptoSHA256Box(context.clone())
        }
    }

    func update(_ data: UnsafeRawBufferPointer) -> Bool {
        state.withLock { context in
            do {
                try context.update(Span(_unsafeElements: data.bindMemory(to: UInt8.self)))
                return true
            } catch {
                return false
            }
        }
    }

    func finalize(into output: UnsafeMutableRawBufferPointer) -> Bool {
        guard output.count == SSLCrypto.SHA256Context.digestByteCount else { return false }
        return state.withLock { context in
            let copy = context.clone()
            do {
                var destination = MutableSpan(_unsafeElements: output.bindMemory(to: UInt8.self))
                try copy.finalize(into: &destination)
                return true
            } catch {
                return false
            }
        }
    }
}

private final class SSLCryptoSHA384Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA384Context>

    init() {
        state = Mutex(SSLCrypto.SHA384Context())
    }

    init(_ context: consuming SSLCrypto.SHA384Context) {
        state = Mutex(consume context)
    }

    func copy() -> SSLCryptoSHA384Box {
        state.withLock { context in
            SSLCryptoSHA384Box(context.clone())
        }
    }

    func update(_ data: UnsafeRawBufferPointer) -> Bool {
        state.withLock { context in
            do {
                try context.update(Span(_unsafeElements: data.bindMemory(to: UInt8.self)))
                return true
            } catch {
                return false
            }
        }
    }

    func finalize(into output: UnsafeMutableRawBufferPointer) -> Bool {
        guard output.count == SSLCrypto.SHA384Context.digestByteCount else { return false }
        return state.withLock { context in
            let copy = context.clone()
            do {
                var destination = MutableSpan(_unsafeElements: output.bindMemory(to: UInt8.self))
                try copy.finalize(into: &destination)
                return true
            } catch {
                return false
            }
        }
    }
}

private final class SSLCryptoSHA512Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA512Context>

    init() {
        state = Mutex(SSLCrypto.SHA512Context())
    }

    init(_ context: consuming SSLCrypto.SHA512Context) {
        state = Mutex(consume context)
    }

    func copy() -> SSLCryptoSHA512Box {
        state.withLock { context in
            SSLCryptoSHA512Box(context.clone())
        }
    }

    func update(_ data: UnsafeRawBufferPointer) -> Bool {
        state.withLock { context in
            do {
                try context.update(Span(_unsafeElements: data.bindMemory(to: UInt8.self)))
                return true
            } catch {
                return false
            }
        }
    }

    func finalize(into output: UnsafeMutableRawBufferPointer) -> Bool {
        guard output.count == SSLCrypto.SHA512Context.digestByteCount else { return false }
        return state.withLock { context in
            let copy = context.clone()
            do {
                var destination = MutableSpan(_unsafeElements: output.bindMemory(to: UInt8.self))
                try copy.finalize(into: &destination)
                return true
            } catch {
                return false
            }
        }
    }
}

public typealias SHA2_256 = SHA256

public struct SHA256: DigestHashFunction, Sendable {
    public static let blockByteCount: Int = 64
    public static let byteCount: Int = 32
    public typealias Digest = SHA256Digest

    private var context: SSLCryptoSHA256Box

    public init() {
        context = SSLCryptoSHA256Box()
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) {
            context = context.copy()
        }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA-256 state")
        }
    }

    public func finalize() -> Self.Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { digestPointer in
            defer { digestPointer.zeroize() }
            guard context.finalize(into: digestPointer) else {
                preconditionFailure("Unable to finalize SHA-256 state")
            }
            guard let digest = SHA256Digest(copying: digestPointer.bytes) else {
                preconditionFailure("Invalid SHA-256 digest size")
            }
            return digest
        }
    }
}

public typealias SHA2_384 = SHA384

public struct SHA384: DigestHashFunction, Sendable {
    public static let blockByteCount: Int = 128
    public static let byteCount: Int = 48
    public typealias Digest = SHA384Digest

    private var context: SSLCryptoSHA384Box

    public init() {
        context = SSLCryptoSHA384Box()
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) {
            context = context.copy()
        }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA-384 state")
        }
    }

    public func finalize() -> Self.Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { digestPointer in
            defer { digestPointer.zeroize() }
            guard context.finalize(into: digestPointer) else {
                preconditionFailure("Unable to finalize SHA-384 state")
            }
            guard let digest = SHA384Digest(copying: digestPointer.bytes) else {
                preconditionFailure("Invalid SHA-384 digest size")
            }
            return digest
        }
    }
}

public typealias SHA2_512 = SHA512

public struct SHA512: DigestHashFunction, Sendable {
    public static let blockByteCount: Int = 128
    public static let byteCount: Int = 64
    public typealias Digest = SHA512Digest

    private var context: SSLCryptoSHA512Box

    public init() {
        context = SSLCryptoSHA512Box()
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) {
            context = context.copy()
        }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA-512 state")
        }
    }

    public func finalize() -> Self.Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { digestPointer in
            defer { digestPointer.zeroize() }
            guard context.finalize(into: digestPointer) else {
                preconditionFailure("Unable to finalize SHA-512 state")
            }
            guard let digest = SHA512Digest(copying: digestPointer.bytes) else {
                preconditionFailure("Invalid SHA-512 digest size")
            }
            return digest
        }
    }
}

#endif
