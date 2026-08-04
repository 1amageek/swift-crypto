//===----------------------------------------------------------------------===//
//
// Pure Swift legacy digest adapters backed by SSLCrypto.
//
// SHA-1 and MD5 remain available only for compatibility. They are not used by
// the secure primitives, and their mutable backend state is still synchronized
// so the Native, WASM, and Embedded contracts stay identical.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

import SSLCrypto
import Synchronization

final class SHA1DigestContext: Sendable {
    private let state: Mutex<SSLCrypto.SHA1Context>

    init() {
        state = Mutex(SSLCrypto.SHA1Context())
    }

    private init(_ context: consuming SSLCrypto.SHA1Context) {
        state = Mutex(consume context)
    }

    func copy() -> SHA1DigestContext {
        state.withLock { SHA1DigestContext($0.clone()) }
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
        guard output.count == SSLCrypto.SHA1Context.digestByteCount else { return false }
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

final class MD5DigestContext: Sendable {
    private let state: Mutex<SSLCrypto.MD5Context>

    init() {
        state = Mutex(SSLCrypto.MD5Context())
    }

    private init(_ context: consuming SSLCrypto.MD5Context) {
        state = Mutex(consume context)
    }

    func copy() -> MD5DigestContext {
        state.withLock { MD5DigestContext($0.clone()) }
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
        guard output.count == SSLCrypto.MD5Context.digestByteCount else { return false }
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

extension Insecure.SHA1 {
    static var digestSize: Int { SSLCrypto.SHA1Context.digestByteCount }

    static func makeContext() -> SHA1DigestContext? { SHA1DigestContext() }

    static func copyContext(_ context: SHA1DigestContext) -> SHA1DigestContext {
        context.copy()
    }

    static func update(_ context: SHA1DigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.update(data)
    }

    static func finalize(
        _ context: SHA1DigestContext,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        context.finalize(into: digest)
    }
}

extension Insecure.MD5 {
    static var digestSize: Int { SSLCrypto.MD5Context.digestByteCount }

    static func makeContext() -> MD5DigestContext? { MD5DigestContext() }

    static func copyContext(_ context: MD5DigestContext) -> MD5DigestContext {
        context.copy()
    }

    static func update(_ context: MD5DigestContext, data: UnsafeRawBufferPointer) -> Bool {
        context.update(data)
    }

    static func finalize(
        _ context: MD5DigestContext,
        digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        context.finalize(into: digest)
    }
}

#endif
