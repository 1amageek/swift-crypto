//===----------------------------------------------------------------------===//
//
// Pure Swift random-byte adapters backed by SSLCrypto.SystemRandom.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

import SSLCrypto

private func fillRandomBytes(_ buffer: UnsafeMutableRawBufferPointer) {
    guard buffer.count > 0 else { return }
    guard let baseAddress = buffer.baseAddress else {
        preconditionFailure("A non-empty random output requires valid storage")
    }
    var span = MutableSpan(
        _unsafeElements: UnsafeMutableBufferPointer(
            start: baseAddress.assumingMemoryBound(to: UInt8.self),
            count: buffer.count
        )
    )
    do {
        try SSLCrypto.SystemRandom.fill(&span)
    } catch {
        preconditionFailure("The secure random number generator failed: \(error)")
    }
}

extension UnsafeMutableRawBufferPointer {
    func initializeWithRandomBytes(count: Int) {
        precondition(count >= 0 && count <= self.count)
        fillRandomBytes(UnsafeMutableRawBufferPointer(rebasing: self.prefix(count)))
    }
}

extension MutableRawSpan {
    mutating func initializeWithRandomBytes(count: Int) {
        precondition(count >= 0 && count <= byteCount)
        withUnsafeMutableBytes { bytes in
            bytes.initializeWithRandomBytes(count: count)
        }
    }
}

extension OutputRawSpan {
    mutating func appendingRandomBytes(count: Int) {
        precondition(count >= 0)
        withUnsafeMutableBytes { buffer, initializedCount in
            precondition(initializedCount <= buffer.count)
            let available = buffer.count - initializedCount
            precondition(count <= available)
            let target = UnsafeMutableRawBufferPointer(
                rebasing: buffer[initializedCount..<(initializedCount + count)]
            )
            target.initializeWithRandomBytes(count: count)
            initializedCount += count
        }
    }
}

#endif
