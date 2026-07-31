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

import CryptoKit
import Foundation

@main
struct SHA256StateSanitizerCommand {
    private static let chunkByteCounts = [1, 2, 3, 7, 31, 55, 63, 64, 65, 127]

    static func main() async {
        for inputByteCount in 0...2_049 {
            validateInput(byteCount: inputByteCount, chunkByteCounts: chunkByteCounts)
        }
        for inputByteCount in [4_095, 4_096, 4_097, 1_048_575, 1_048_576, 1_048_577] {
            validateInput(byteCount: inputByteCount, chunkByteCounts: [63, 64, 65, 4_097])
        }

        validateCopyDivergence()
        await validateConcurrentCopies()
        validateRepeatedFinalize()
        validateMisalignedInputs()
        validateOutputBounds()
        validateOutputCanaries()
        print("SHA-256 sanitizer validation passed")
    }

    private static func validateInput(byteCount: Int, chunkByteCounts: [Int]) {
        let input = makeInput(byteCount: byteCount)
        let expected = Array(CryptoKit.SHA256.hash(data: input))
        precondition(
            oneShotDigest(input) == expected,
            "SHA-256 contiguous one-shot validation failed"
        )

        for chunkByteCount in chunkByteCounts {
            let actual = digest(input, chunkByteCount: chunkByteCount)
            precondition(actual == expected, "SHA-256 differential validation failed")
        }
    }

    private static func oneShotDigest(_ input: [UInt8]) -> [UInt8] {
        input.withUnsafeBytes { inputBytes in
            withUnsafeTemporaryAllocation(byteCount: 32, alignment: 1) { output in
                precondition(
                    SHA256State.hash(inputBytes, into: output),
                    "SHA-256 contiguous one-shot finalization failed"
                )
                return Array(output)
            }
        }
    }

    private static func makeInput(byteCount: Int) -> [UInt8] {
        (0..<byteCount).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 17) }
    }

    private static func digest(_ input: [UInt8], chunkByteCount: Int) -> [UInt8] {
        var state = SHA256State()
        input.withUnsafeBytes { inputBytes in
            var offset = 0
            while offset < inputBytes.count {
                let end = min(offset + chunkByteCount, inputBytes.count)
                state.update(.init(rebasing: inputBytes[offset..<end]))
                offset = end
            }
        }
        return finalizedDigest(of: state)
    }

    private static func finalizedDigest(of state: SHA256State) -> [UInt8] {
        withUnsafeTemporaryAllocation(byteCount: 32, alignment: 1) { output in
            precondition(state.finalize(into: output), "SHA-256 finalization failed")
            return Array(output)
        }
    }

    private static func validateCopyDivergence() {
        let prefix = makeInput(byteCount: 91)
        let firstSuffix = makeInput(byteCount: 137)
        let secondSuffix = makeInput(byteCount: 211)
        var first = SHA256State()
        prefix.withUnsafeBytes { first.update($0) }
        var second = first
        firstSuffix.withUnsafeBytes { first.update($0) }
        secondSuffix.withUnsafeBytes { second.update($0) }

        let firstExpected = Array(CryptoKit.SHA256.hash(data: prefix + firstSuffix))
        let secondExpected = Array(CryptoKit.SHA256.hash(data: prefix + secondSuffix))
        precondition(finalizedDigest(of: first) == firstExpected)
        precondition(finalizedDigest(of: second) == secondExpected)
    }

    private static func validateRepeatedFinalize() {
        let input = makeInput(byteCount: 257)
        var state = SHA256State()
        input.withUnsafeBytes { state.update($0) }
        let first = finalizedDigest(of: state)
        let second = finalizedDigest(of: state)
        precondition(first == second, "SHA-256 repeated finalization changed its result")
    }

    private static func validateConcurrentCopies() async {
        let prefix = makeInput(byteCount: 193)
        var prefixState = SHA256State()
        prefix.withUnsafeBytes { prefixState.update($0) }
        let sharedPrefixState = prefixState

        await withTaskGroup(of: Void.self) { group in
            for taskIndex in 0..<32 {
                let suffix = makeInput(byteCount: 55 + taskIndex)
                group.addTask {
                    var localState = sharedPrefixState
                    suffix.withUnsafeBytes { localState.update($0) }
                    let expected = Array(CryptoKit.SHA256.hash(data: prefix + suffix))
                    precondition(
                        finalizedDigest(of: localState) == expected,
                        "Concurrent SHA-256 copy-on-write validation failed"
                    )
                }
            }
        }
    }

    private static func validateMisalignedInputs() {
        for inputByteCount in [64, 65, 127, 128, 129, 1_024, 1_025] {
            let storage = makeInput(byteCount: inputByteCount + 1)
            let expected = Array(CryptoKit.SHA256.hash(data: storage.dropFirst()))

            storage.withUnsafeBytes { storageBytes in
                let input = UnsafeRawBufferPointer(
                    rebasing: storageBytes[1..<inputByteCount + 1]
                )
                let alignmentRemainder =
                    Int(bitPattern: input.baseAddress!) % MemoryLayout<UInt32>.alignment
                precondition(
                    alignmentRemainder != 0,
                    "Misaligned SHA-256 validation input is actually aligned"
                )

                withUnsafeTemporaryAllocation(byteCount: 32, alignment: 1) { output in
                    precondition(SHA256State.hash(input, into: output))
                    precondition(Array(output) == expected)
                }

                var state = SHA256State()
                state.update(input)
                precondition(finalizedDigest(of: state) == expected)
            }
        }
    }

    private static func validateOutputBounds() {
        let state = SHA256State()
        withUnsafeTemporaryAllocation(byteCount: 31, alignment: 1) { output in
            precondition(!state.finalize(into: output), "Undersized SHA-256 output was accepted")
        }
        withUnsafeTemporaryAllocation(byteCount: 33, alignment: 1) { output in
            precondition(!state.finalize(into: output), "Oversized SHA-256 output was accepted")
        }
        precondition(
            !state.finalize(into: .init(start: nil, count: 0)),
            "Empty SHA-256 output was accepted"
        )

        let input = makeInput(byteCount: 65)
        input.withUnsafeBytes { inputBytes in
            withUnsafeTemporaryAllocation(byteCount: 31, alignment: 1) { output in
                precondition(
                    !SHA256State.hash(inputBytes, into: output),
                    "Undersized static SHA-256 output was accepted"
                )
            }
            withUnsafeTemporaryAllocation(byteCount: 33, alignment: 1) { output in
                precondition(
                    !SHA256State.hash(inputBytes, into: output),
                    "Oversized static SHA-256 output was accepted"
                )
            }
            precondition(
                !SHA256State.hash(inputBytes, into: .init(start: nil, count: 0)),
                "Empty static SHA-256 output was accepted"
            )
        }
    }

    private static func validateOutputCanaries() {
        let input = makeInput(byteCount: 257)
        let expected = Array(CryptoKit.SHA256.hash(data: input))
        let canary: UInt8 = 0xa5

        var state = SHA256State()
        input.withUnsafeBytes { state.update($0) }
        var instanceOutput = [UInt8](repeating: canary, count: 34)
        instanceOutput.withUnsafeMutableBytes { outputBytes in
            let digest = UnsafeMutableRawBufferPointer(rebasing: outputBytes[1..<33])
            precondition(state.finalize(into: digest))
        }
        precondition(instanceOutput.first == canary && instanceOutput.last == canary)
        precondition(Array(instanceOutput[1..<33]) == expected)

        var staticOutput = [UInt8](repeating: canary, count: 34)
        input.withUnsafeBytes { inputBytes in
            staticOutput.withUnsafeMutableBytes { outputBytes in
                let digest = UnsafeMutableRawBufferPointer(rebasing: outputBytes[1..<33])
                precondition(SHA256State.hash(inputBytes, into: digest))
            }
        }
        precondition(staticOutput.first == canary && staticOutput.last == canary)
        precondition(Array(staticOutput[1..<33]) == expected)
    }
}
