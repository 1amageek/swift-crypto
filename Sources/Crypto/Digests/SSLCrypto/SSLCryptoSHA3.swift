//===----------------------------------------------------------------------===//
//
// Pure Swift SHA-3 adapters backed by SSLCrypto.
//
// The facade preserves Crypto's copy-on-write value semantics. Each mutable
// backend context is owned by a synchronized box, and finalization operates on
// a cloned context so the caller's value is never mutated by observation.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

import SSLCrypto
import Synchronization

private final class SSLCryptoSHA3_256Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA3_256Context>

    init() {
        state = Mutex(SSLCrypto.SHA3_256Context())
    }

    func copy() -> SSLCryptoSHA3_256Box {
        state.withLock { SSLCryptoSHA3_256Box($0.clone()) }
    }

    private init(_ context: consuming SSLCrypto.SHA3_256Context) {
        state = Mutex(consume context)
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
        guard output.count == SSLCrypto.SHA3_256Context.digestByteCount else { return false }
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

private final class SSLCryptoSHA3_384Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA3_384Context>

    init() {
        state = Mutex(SSLCrypto.SHA3_384Context())
    }

    func copy() -> SSLCryptoSHA3_384Box {
        state.withLock { SSLCryptoSHA3_384Box($0.clone()) }
    }

    private init(_ context: consuming SSLCrypto.SHA3_384Context) {
        state = Mutex(consume context)
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
        guard output.count == SSLCrypto.SHA3_384Context.digestByteCount else { return false }
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

private final class SSLCryptoSHA3_512Box: Sendable {
    private let state: Mutex<SSLCrypto.SHA3_512Context>

    init() {
        state = Mutex(SSLCrypto.SHA3_512Context())
    }

    func copy() -> SSLCryptoSHA3_512Box {
        state.withLock { SSLCryptoSHA3_512Box($0.clone()) }
    }

    private init(_ context: consuming SSLCrypto.SHA3_512Context) {
        state = Mutex(consume context)
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
        guard output.count == SSLCrypto.SHA3_512Context.digestByteCount else { return false }
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

public struct SHA3_256: DigestHashFunction, Sendable {
    public static let blockByteCount = 136
    public static let byteCount = 32
    public typealias Digest = SHA3_256Digest

    private var context: SSLCryptoSHA3_256Box

    public init() { context = SSLCryptoSHA3_256Box() }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) { context = context.copy() }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA3-256 state")
        }
    }

    public func finalize() -> Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { output in
            defer { output.zeroize() }
            guard context.finalize(into: output), let digest = Digest(copying: output.bytes) else {
                preconditionFailure("Unable to finalize SHA3-256 state")
            }
            return digest
        }
    }
}

public struct SHA3_384: DigestHashFunction, Sendable {
    public static let blockByteCount = 104
    public static let byteCount = 48
    public typealias Digest = SHA3_384Digest

    private var context: SSLCryptoSHA3_384Box

    public init() { context = SSLCryptoSHA3_384Box() }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) { context = context.copy() }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA3-384 state")
        }
    }

    public func finalize() -> Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { output in
            defer { output.zeroize() }
            guard context.finalize(into: output), let digest = Digest(copying: output.bytes) else {
                preconditionFailure("Unable to finalize SHA3-384 state")
            }
            return digest
        }
    }
}

public struct SHA3_512: DigestHashFunction, Sendable {
    public static let blockByteCount = 72
    public static let byteCount = 64
    public typealias Digest = SHA3_512Digest

    private var context: SSLCryptoSHA3_512Box

    public init() { context = SSLCryptoSHA3_512Box() }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&context) { context = context.copy() }
        guard context.update(bufferPointer) else {
            preconditionFailure("Unable to update SHA3-512 state")
        }
    }

    public func finalize() -> Digest {
        withUnsafeTemporaryAllocation(byteCount: Self.byteCount, alignment: 1) { output in
            defer { output.zeroize() }
            guard context.finalize(into: output), let digest = Digest(copying: output.bytes) else {
                preconditionFailure("Unable to finalize SHA3-512 state")
            }
            return digest
        }
    }
}

#endif
