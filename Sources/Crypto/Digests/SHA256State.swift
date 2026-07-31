//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if !canImport(CryptoKit) || CRYPTO_SHA256_STATE_STANDALONE_VALIDATION

/// A value-semantic SHA-256 state with copy-on-write secure storage.
///
/// Unsafe invariants:
/// - ARC owns each storage object and invokes exactly one deinitializer, which
///   zeroizes the persistent state and inline 64-byte buffer exactly once.
/// - Shared storage is immutable. Every update first establishes unique
///   ownership, so distinct value copies cannot race through the backing class.
/// - `state`, `buffer`, and every message-schedule element are initialized for
///   their entire lifetime.
/// - Input pointers are borrowed only during `update` and never escape.
/// - `compress` is called only with a nonnull pointer to at least 64 readable
///   bytes. Its unaligned loads therefore require no alignment assumption.
/// - Unchecked state indices are constants in `0...7`; schedule indices are
///   either in `0..<16` or masked with `15` before access.
/// - Storage cannot alias borrowed input, and mutable views never escape their
///   scoped closure or cross a Sendable boundary.
struct SHA256State: Sendable {
    private var storage: Storage

    init() {
        storage = Storage()
    }

    @inline(__always)
    mutating func update(_ input: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&storage) {
            storage = Storage(copying: storage)
        }
        storage.update(input)
    }

    func finalize(into digest: UnsafeMutableRawBufferPointer) -> Bool {
        storage.finalize(into: digest)
    }

    static func hash(
        _ input: UnsafeRawBufferPointer,
        into digest: UnsafeMutableRawBufferPointer
    ) -> Bool {
        Storage.hash(input, into: digest)
    }

    /// The compiler cannot prove this class safe because its fields mutate.
    /// Mutation is reachable only after the enclosing value establishes unique
    /// ownership; shared instances are read-only and deinitialize at refcount zero.
    private final class Storage: @unchecked Sendable {
        private static let blockByteCount = 64
        private static let digestByteCount = 32

        private static let initialState: [8 of UInt32] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ]

        private static let roundConstants: [64 of UInt32] = [
            0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
            0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
            0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
            0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
            0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
            0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
            0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
            0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
            0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
            0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
            0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
            0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
            0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
            0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
            0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
            0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
        ]

        private var state = Storage.initialState
        private var buffer: [64 of UInt8] = .init(repeating: 0)
        private var bufferedByteCount = 0
        private var totalByteCount: UInt64 = 0

        init() {}

        init(copying other: Storage) {
            state = other.state
            buffer = other.buffer
            bufferedByteCount = other.bufferedByteCount
            totalByteCount = other.totalByteCount
        }

        deinit {
            withUnsafeMutableBytes(of: &state) { $0.zeroize() }
            withUnsafeMutableBytes(of: &buffer) { $0.zeroize() }
        }

        @inline(__always)
        func update(_ input: UnsafeRawBufferPointer) {
            guard !input.isEmpty else {
                return
            }
            guard let inputBaseAddress = input.baseAddress else {
                preconditionFailure("Nonempty SHA-256 input has no base address")
            }

            totalByteCount &+= UInt64(input.count)
            if bufferedByteCount == 0 && input.count == Self.blockByteCount {
                Self.compress(inputBaseAddress, state: &state)
                return
            }

            var inputOffset = 0

            if bufferedByteCount > 0 {
                let copiedByteCount = min(Self.blockByteCount - bufferedByteCount, input.count)
                copyInput(
                    from: inputBaseAddress,
                    sourceOffset: 0,
                    byteCount: copiedByteCount,
                    destinationOffset: bufferedByteCount
                )
                bufferedByteCount += copiedByteCount
                inputOffset = copiedByteCount

                if bufferedByteCount == Self.blockByteCount {
                    buffer.span.withUnsafeBytes { block in
                        Self.compress(block.baseAddress!, state: &state)
                    }
                    bufferedByteCount = 0
                }
            }

            let directlyCompressibleByteCount =
                (input.count - inputOffset) & ~(Self.blockByteCount - 1)
            let directEndOffset = inputOffset + directlyCompressibleByteCount
            while inputOffset < directEndOffset {
                Self.compress(inputBaseAddress.advanced(by: inputOffset), state: &state)
                inputOffset += Self.blockByteCount
            }

            let remainingByteCount = input.count - inputOffset
            if remainingByteCount > 0 {
                copyInput(
                    from: inputBaseAddress,
                    sourceOffset: inputOffset,
                    byteCount: remainingByteCount,
                    destinationOffset: 0
                )
                bufferedByteCount = remainingByteCount
            }
        }

        static func hash(
            _ input: UnsafeRawBufferPointer,
            into digest: UnsafeMutableRawBufferPointer
        ) -> Bool {
            guard digest.count == Self.digestByteCount, let digestBaseAddress = digest.baseAddress else {
                return false
            }
            if !input.isEmpty && input.baseAddress == nil {
                preconditionFailure("Nonempty SHA-256 input has no base address")
            }

            var state = Self.initialState
            defer {
                withUnsafeMutableBytes(of: &state) { $0.zeroize() }
            }

            let directlyCompressibleByteCount =
                input.count & ~(Self.blockByteCount - 1)
            var inputOffset = 0
            while inputOffset < directlyCompressibleByteCount {
                Self.compress(input.baseAddress!.advanced(by: inputOffset), state: &state)
                inputOffset += Self.blockByteCount
            }

            let bitCount = UInt64(input.count) &* 8
            let remainingByteCount = input.count - inputOffset
            if remainingByteCount == 0 {
                Self.compressPaddingBlock(bitCount: bitCount, state: &state)
            } else {
                var finalBlock: [64 of UInt8] = .init(repeating: 0)
                defer {
                    withUnsafeMutableBytes(of: &finalBlock) { $0.zeroize() }
                }
                withUnsafeMutableBytes(of: &finalBlock) {
                    $0.baseAddress!.copyMemory(
                        from: input.baseAddress!.advanced(by: inputOffset),
                        byteCount: remainingByteCount
                    )
                }
                finalBlock[unchecked: remainingByteCount] = 0x80

                if remainingByteCount >= 56 {
                    finalBlock.span.withUnsafeBytes { block in
                        Self.compress(block.baseAddress!, state: &state)
                    }
                    finalBlock = .init(repeating: 0)
                }

                for byteIndex in 0..<8 {
                    let shift = UInt64((7 - byteIndex) * 8)
                    finalBlock[unchecked: 56 + byteIndex] = UInt8(truncatingIfNeeded: bitCount >> shift)
                }
                finalBlock.span.withUnsafeBytes { block in
                    Self.compress(block.baseAddress!, state: &state)
                }
            }

            Self.writeDigest(state, to: digestBaseAddress)
            return true
        }

        func finalize(into digest: UnsafeMutableRawBufferPointer) -> Bool {
            guard digest.count == Self.digestByteCount, let digestBaseAddress = digest.baseAddress else {
                return false
            }

            var finalState = state
            defer {
                withUnsafeMutableBytes(of: &finalState) { $0.zeroize() }
            }
            let bitCount = totalByteCount &* 8
            if bufferedByteCount == 0 {
                Self.compressPaddingBlock(bitCount: bitCount, state: &finalState)
            } else {
                var finalBlock: [64 of UInt8] = .init(repeating: 0)
                defer {
                    withUnsafeMutableBytes(of: &finalBlock) { $0.zeroize() }
                }
                buffer.span.withUnsafeBytes { bufferedInput in
                    withUnsafeMutableBytes(of: &finalBlock) {
                        $0.baseAddress!.copyMemory(
                            from: bufferedInput.baseAddress!,
                            byteCount: bufferedByteCount
                        )
                    }
                }
                let paddingOffset = bufferedByteCount + 1
                finalBlock[unchecked: bufferedByteCount] = 0x80

                if paddingOffset > 56 {
                    finalBlock.span.withUnsafeBytes { block in
                        Self.compress(block.baseAddress!, state: &finalState)
                    }
                    finalBlock = .init(repeating: 0)
                }

                for byteIndex in 0..<8 {
                    let shift = UInt64((7 - byteIndex) * 8)
                    finalBlock[unchecked: 56 + byteIndex] = UInt8(truncatingIfNeeded: bitCount >> shift)
                }
                finalBlock.span.withUnsafeBytes { block in
                    Self.compress(block.baseAddress!, state: &finalState)
                }
            }

            Self.writeDigest(finalState, to: digestBaseAddress)
            return true
        }

        @inline(__always)
        private static func writeDigest(
            _ state: [8 of UInt32],
            to digest: UnsafeMutableRawPointer
        ) {
            for wordIndex in 0..<8 {
                let word = state[unchecked: wordIndex]
                let outputOffset = wordIndex * 4
                digest.storeBytes(
                    of: UInt8(truncatingIfNeeded: word >> 24),
                    toByteOffset: outputOffset,
                    as: UInt8.self
                )
                digest.storeBytes(
                    of: UInt8(truncatingIfNeeded: word >> 16),
                    toByteOffset: outputOffset + 1,
                    as: UInt8.self
                )
                digest.storeBytes(
                    of: UInt8(truncatingIfNeeded: word >> 8),
                    toByteOffset: outputOffset + 2,
                    as: UInt8.self
                )
                digest.storeBytes(
                    of: UInt8(truncatingIfNeeded: word),
                    toByteOffset: outputOffset + 3,
                    as: UInt8.self
                )
            }
        }

        @inline(__always)
        private func copyInput(
            from source: UnsafeRawPointer,
            sourceOffset: Int,
            byteCount: Int,
            destinationOffset: Int
        ) {
            precondition(sourceOffset >= 0)
            precondition(byteCount > 0)
            precondition(destinationOffset >= 0)
            precondition(byteCount <= Self.blockByteCount)
            precondition(destinationOffset <= Self.blockByteCount - byteCount)

            withUnsafeMutableBytes(of: &buffer) { destination in
                destination.baseAddress!.advanced(by: destinationOffset).copyMemory(
                    from: source.advanced(by: sourceOffset),
                    byteCount: byteCount
                )
            }
        }

        /// Compresses one complete block borrowed from initialized input memory.
        ///
        /// The caller proves that `block` is nonnull and covers at least 64 bytes.
        /// Loads are explicitly unaligned, every fixed array is initialized, and
        /// all unchecked indices are bounded by constants or a `15` mask.
        @inline(never)
        private static func compress(
            _ block: UnsafeRawPointer,
            state: inout [8 of UInt32]
        ) {
            var schedule: [16 of UInt32] = .init(repeating: 0)
            schedule[unchecked: 0] = loadWord(from: block, at: 0)
            schedule[unchecked: 1] = loadWord(from: block, at: 1)
            schedule[unchecked: 2] = loadWord(from: block, at: 2)
            schedule[unchecked: 3] = loadWord(from: block, at: 3)
            schedule[unchecked: 4] = loadWord(from: block, at: 4)
            schedule[unchecked: 5] = loadWord(from: block, at: 5)
            schedule[unchecked: 6] = loadWord(from: block, at: 6)
            schedule[unchecked: 7] = loadWord(from: block, at: 7)
            schedule[unchecked: 8] = loadWord(from: block, at: 8)
            schedule[unchecked: 9] = loadWord(from: block, at: 9)
            schedule[unchecked: 10] = loadWord(from: block, at: 10)
            schedule[unchecked: 11] = loadWord(from: block, at: 11)
            schedule[unchecked: 12] = loadWord(from: block, at: 12)
            schedule[unchecked: 13] = loadWord(from: block, at: 13)
            schedule[unchecked: 14] = loadWord(from: block, at: 14)
            schedule[unchecked: 15] = loadWord(from: block, at: 15)
            compress(schedule: &schedule, state: &state)
        }

        /// Compresses the single padding block used after a block-aligned message.
        ///
        /// This avoids materializing, loading, and byte-swapping a 64-byte block
        /// whose contents are known except for the encoded message length.
        @inline(never)
        private static func compressPaddingBlock(
            bitCount: UInt64,
            state: inout [8 of UInt32]
        ) {
            var schedule: [16 of UInt32] = [
                0x8000_0000, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0,
                UInt32(truncatingIfNeeded: bitCount >> 32),
                UInt32(truncatingIfNeeded: bitCount),
            ]
            compress(schedule: &schedule, state: &state)
        }

        @inline(__always)
        private static func compress(
            schedule: inout [16 of UInt32],
            state: inout [8 of UInt32]
        ) {
            var a = state[unchecked: 0]
            var b = state[unchecked: 1]
            var c = state[unchecked: 2]
            var d = state[unchecked: 3]
            var e = state[unchecked: 4]
            var f = state[unchecked: 5]
            var g = state[unchecked: 6]
            var h = state[unchecked: 7]

            round(a, b, c, &d, e, f, g, &h, schedule[unchecked: 0], Self.roundConstants[unchecked: 0])
            round(h, a, b, &c, d, e, f, &g, schedule[unchecked: 1], Self.roundConstants[unchecked: 1])
            round(g, h, a, &b, c, d, e, &f, schedule[unchecked: 2], Self.roundConstants[unchecked: 2])
            round(f, g, h, &a, b, c, d, &e, schedule[unchecked: 3], Self.roundConstants[unchecked: 3])
            round(e, f, g, &h, a, b, c, &d, schedule[unchecked: 4], Self.roundConstants[unchecked: 4])
            round(d, e, f, &g, h, a, b, &c, schedule[unchecked: 5], Self.roundConstants[unchecked: 5])
            round(c, d, e, &f, g, h, a, &b, schedule[unchecked: 6], Self.roundConstants[unchecked: 6])
            round(b, c, d, &e, f, g, h, &a, schedule[unchecked: 7], Self.roundConstants[unchecked: 7])
            round(a, b, c, &d, e, f, g, &h, schedule[unchecked: 8], Self.roundConstants[unchecked: 8])
            round(h, a, b, &c, d, e, f, &g, schedule[unchecked: 9], Self.roundConstants[unchecked: 9])
            round(g, h, a, &b, c, d, e, &f, schedule[unchecked: 10], Self.roundConstants[unchecked: 10])
            round(f, g, h, &a, b, c, d, &e, schedule[unchecked: 11], Self.roundConstants[unchecked: 11])
            round(e, f, g, &h, a, b, c, &d, schedule[unchecked: 12], Self.roundConstants[unchecked: 12])
            round(d, e, f, &g, h, a, b, &c, schedule[unchecked: 13], Self.roundConstants[unchecked: 13])
            round(c, d, e, &f, g, h, a, &b, schedule[unchecked: 14], Self.roundConstants[unchecked: 14])
            round(b, c, d, &e, f, g, h, &a, schedule[unchecked: 15], Self.roundConstants[unchecked: 15])

            for roundStart in stride(from: 16, to: 64, by: 8) {
                let word0 = expandedWord(in: &schedule, for: roundStart)
                round(a, b, c, &d, e, f, g, &h, word0, Self.roundConstants[unchecked: roundStart])
                let word1 = expandedWord(in: &schedule, for: roundStart + 1)
                round(h, a, b, &c, d, e, f, &g, word1, Self.roundConstants[unchecked: roundStart + 1])
                let word2 = expandedWord(in: &schedule, for: roundStart + 2)
                round(g, h, a, &b, c, d, e, &f, word2, Self.roundConstants[unchecked: roundStart + 2])
                let word3 = expandedWord(in: &schedule, for: roundStart + 3)
                round(f, g, h, &a, b, c, d, &e, word3, Self.roundConstants[unchecked: roundStart + 3])
                let word4 = expandedWord(in: &schedule, for: roundStart + 4)
                round(e, f, g, &h, a, b, c, &d, word4, Self.roundConstants[unchecked: roundStart + 4])
                let word5 = expandedWord(in: &schedule, for: roundStart + 5)
                round(d, e, f, &g, h, a, b, &c, word5, Self.roundConstants[unchecked: roundStart + 5])
                let word6 = expandedWord(in: &schedule, for: roundStart + 6)
                round(c, d, e, &f, g, h, a, &b, word6, Self.roundConstants[unchecked: roundStart + 6])
                let word7 = expandedWord(in: &schedule, for: roundStart + 7)
                round(b, c, d, &e, f, g, h, &a, word7, Self.roundConstants[unchecked: roundStart + 7])
            }

            state[unchecked: 0] &+= a
            state[unchecked: 1] &+= b
            state[unchecked: 2] &+= c
            state[unchecked: 3] &+= d
            state[unchecked: 4] &+= e
            state[unchecked: 5] &+= f
            state[unchecked: 6] &+= g
            state[unchecked: 7] &+= h
        }

        @inline(__always)
        private static func loadWord(from block: UnsafeRawPointer, at index: Int) -> UInt32 {
            block.loadUnaligned(
                fromByteOffset: index * MemoryLayout<UInt32>.stride,
                as: UInt32.self
            ).bigEndian
        }

        @inline(__always)
        private static func expandedWord(
            in schedule: inout [16 of UInt32],
            for round: Int
        ) -> UInt32 {
            let index = round & 15
            let word =
                schedule[unchecked: index]
                &+ smallSigma0(schedule[unchecked: (round + 1) & 15])
                &+ schedule[unchecked: (round + 9) & 15]
                &+ smallSigma1(schedule[unchecked: (round + 14) & 15])
            schedule[unchecked: index] = word
            return word
        }

        @inline(__always)
        private static func round(
            _ a: UInt32,
            _ b: UInt32,
            _ c: UInt32,
            _ d: inout UInt32,
            _ e: UInt32,
            _ f: UInt32,
            _ g: UInt32,
            _ h: inout UInt32,
            _ word: UInt32,
            _ constant: UInt32
        ) {
            let choice = (e & (f ^ g)) ^ g
            let majority = (a & b) ^ (c & (a ^ b))
            let temporary = h &+ bigSigma1(e) &+ choice &+ constant &+ word
            h = bigSigma0(a) &+ majority &+ temporary
            d &+= temporary
        }

        @inline(__always)
        private static func rotateRight(_ value: UInt32, by count: UInt32) -> UInt32 {
            (value >> count) | (value << (32 - count))
        }

        @inline(__always)
        private static func bigSigma0(_ value: UInt32) -> UInt32 {
            rotateRight(value, by: 2) ^ rotateRight(value, by: 13) ^ rotateRight(value, by: 22)
        }

        @inline(__always)
        private static func bigSigma1(_ value: UInt32) -> UInt32 {
            rotateRight(value, by: 6) ^ rotateRight(value, by: 11) ^ rotateRight(value, by: 25)
        }

        @inline(__always)
        private static func smallSigma0(_ value: UInt32) -> UInt32 {
            rotateRight(value, by: 7) ^ rotateRight(value, by: 18) ^ (value >> 3)
        }

        @inline(__always)
        private static func smallSigma1(_ value: UInt32) -> UInt32 {
            rotateRight(value, by: 17) ^ rotateRight(value, by: 19) ^ (value >> 10)
        }
    }
}

#endif
