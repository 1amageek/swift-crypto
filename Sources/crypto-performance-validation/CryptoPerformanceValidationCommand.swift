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

internal import CCryptoBoringSSL
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

#if os(WASI)
import WASILibc
#endif

/// Measures the Pure Swift SHA-256 implementation against direct BoringSSL.
@main
struct CryptoPerformanceValidationCommand {
    private static let boringSSLCommit = "0226f30467f540a3f62ef48d453f93927da199b6"
    private static let sampleCount = 11
    private static let warmupCount = 1
    private static let maximumIterationsPerSample = 4_096
    private static let targetThroughputMultiplier = 1.1
    private static let maximumMedianTimeRatio = 1.0 / targetThroughputMultiplier
    private static let throughputGateMinimumByteCount = 1_048_576

    private static let diagnosticByteCountPerSample = 1024 * 1024
    private static let throughputByteCountPerSample = 4 * 1024 * 1024

    static func main() {
        #if os(WASI) && !canImport(CryptoKit)
        runBenchmarks()
        #else
        fatalError("Pure Swift SHA-256 performance validation requires WASI")
        #endif
    }

    private static func runBenchmarks() {
        let inputByteCounts = [1_048_576, 1_048_577, 16_384, 16_385, 64, 65]
        let inputStorage = makeInput(byteCount: inputByteCounts.max()! + 1)
        var checksum: UInt64 = 0
        var results: [ComparisonResult] = []

        validateBoundaryInputs()
        print("benchmark,sha256-pure-swift-versus-boringssl")
        print("backend,pure-swift-sha256")
        #if hasFeature(Embedded)
        print("runtime,embedded-wasm")
        #else
        print("runtime,wasi")
        #endif
        print("reference,boringssl,\(boringSSLCommit)")
        print("reference_backend,portable-no-asm")
        print("validation,boundary-differential,passed")
        print("target_throughput_multiplier,\(targetThroughputMultiplier)")
        print("maximum_median_time_ratio,\(maximumMedianTimeRatio)")
        print("throughput_gate_minimum_bytes,\(throughputGateMinimumByteCount)")
        print("samples,\(sampleCount)")
        print("warmups,\(warmupCount)")
        print(
            "RESULT_HEADER,operation,input_bytes,iterations,direct_median_ns,"
                + "public_median_ns,paired_median_ratio,paired_p90_ratio,target_gate"
        )
        print(
            "SAMPLE_HEADER,operation,input_bytes,sample_index,direct_ns,public_ns,"
                + "paired_ratio,direct_checksum,public_checksum"
        )

        for inputByteCount in inputByteCounts {
            print("CASE_START,\(inputByteCount)")
            let input = inputStorage[..<inputByteCount]
            validate(input)
            print("CASE_VALIDATION_PASSED,\(inputByteCount)")
            let iterations = iterationsPerSample(inputByteCount: inputByteCount)
            let isThroughputGate = inputByteCount >= throughputGateMinimumByteCount

            let oneShot = compare(
                operation: "one-shot",
                inputByteCount: inputByteCount,
                iterations: iterations,
                isTargetGate: isThroughputGate,
                direct: { runBoringSSLOneShot(input: input, iterations: $0) },
                publicAPI: { runCryptoOneShot(input: input, iterations: $0) }
            )
            print(oneShot.csv)
            checksum &+= oneShot.checksum
            results.append(oneShot)

            let rawSpanOneShot = compare(
                operation: "raw-span-one-shot",
                inputByteCount: inputByteCount,
                iterations: iterations,
                isTargetGate: isThroughputGate,
                direct: { runBoringSSLOneShot(input: input, iterations: $0) },
                publicAPI: { runCryptoRawSpanOneShot(input: input, iterations: $0) }
            )
            print(rawSpanOneShot.csv)
            checksum &+= rawSpanOneShot.checksum
            results.append(rawSpanOneShot)

            let incremental = compare(
                operation: "incremental-64-byte-chunks",
                inputByteCount: inputByteCount,
                iterations: iterations,
                isTargetGate: isThroughputGate,
                direct: { runBoringSSLIncremental(input: input, iterations: $0) },
                publicAPI: { runCryptoIncremental(input: input, iterations: $0) }
            )
            print(incremental.csv)
            checksum &+= incremental.checksum
            results.append(incremental)

            if inputByteCount == 16_385 {
                let fragmentedIterations = min(iterations, 32)
                for chunkByteCount in [7, 55, 65] {
                    let fragmented = compare(
                        operation: "incremental-\(chunkByteCount)-byte-chunks",
                        inputByteCount: inputByteCount,
                        iterations: fragmentedIterations,
                        isTargetGate: false,
                        direct: {
                            runBoringSSLIncremental(
                                input: input,
                                iterations: $0,
                                chunkByteCount: chunkByteCount
                            )
                        },
                        publicAPI: {
                            runCryptoIncremental(
                                input: input,
                                iterations: $0,
                                chunkByteCount: chunkByteCount
                            )
                        }
                    )
                    print(fragmented.csv)
                    checksum &+= fragmented.checksum
                    results.append(fragmented)
                }
            }

            if [65, 16_385, 1_048_577].contains(inputByteCount) {
                let misalignedInput = inputStorage[1..<inputByteCount + 1]
                validateUnalignedInput(misalignedInput)
                validate(misalignedInput)
                let misaligned = compare(
                    operation: "raw-span-one-shot-unaligned",
                    inputByteCount: inputByteCount,
                    iterations: iterations,
                    isTargetGate: isThroughputGate,
                    direct: {
                        runBoringSSLOneShot(input: misalignedInput, iterations: $0)
                    },
                    publicAPI: {
                        runCryptoRawSpanOneShot(input: misalignedInput, iterations: $0)
                    }
                )
                print(misaligned.csv)
                checksum &+= misaligned.checksum
                results.append(misaligned)
            }
        }

        let failures = results.filter {
            $0.isTargetGate && $0.pairedMedianRatio > maximumMedianTimeRatio
        }
        for failure in failures {
            print("TARGET_FAILURE,\(failure.operation),\(failure.inputByteCount),\(failure.pairedMedianRatio)")
        }
        print(
            "SUMMARY,\(failures.isEmpty ? "target_passed" : "target_failed"),"
                + "checksum,\(checksum)"
        )
        #if os(WASI)
        fflush(nil)
        if !failures.isEmpty {
            exit(EXIT_FAILURE)
        }
        #else
        precondition(failures.isEmpty, "Pure Swift SHA-256 missed its throughput target")
        #endif
    }

    private static func iterationsPerSample(inputByteCount: Int) -> Int {
        let targetByteCount =
            inputByteCount >= throughputGateMinimumByteCount
            ? throughputByteCountPerSample : diagnosticByteCountPerSample
        let requiredIterations =
            (targetByteCount + inputByteCount - 1) / inputByteCount
        return min(maximumIterationsPerSample, max(1, requiredIterations))
    }

    private static func makeInput(byteCount: Int) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: byteCount) { buffer, initializedCount in
            for index in buffer.indices {
                buffer[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 17)
            }
            initializedCount = byteCount
        }
    }

    private static func validate<Input: DataProtocol & ContiguousBytes>(
        _ input: borrowing Input
    ) {
        let direct = boringSSLHash(input)
        let publicAPI = SHA256.hash(data: input)
        precondition(publicAPI.elementsEqual(direct), "SHA-256 implementations disagree")
        let rawSpan = input.withUnsafeBytes { SHA256.hash(bytes: $0.bytes) }
        precondition(rawSpan.elementsEqual(direct), "SHA-256 RawSpan implementation disagrees")
    }

    private static func validateUnalignedInput(_ input: ArraySlice<UInt8>) {
        let alignmentRemainder = input.withUnsafeBytes { inputBytes in
            guard let baseAddress = inputBytes.baseAddress else {
                preconditionFailure("Nonempty unaligned validation input has no base address")
            }
            return Int(bitPattern: baseAddress) % MemoryLayout<UInt32>.alignment
        }
        precondition(alignmentRemainder != 0, "Unaligned SHA-256 case is actually aligned")
        print(
            "UNALIGNED_POINTER,\(input.count),alignment_remainder,\(alignmentRemainder)"
        )
    }

    private static func validateBoundaryInputs() {
        let inputByteCounts = [
            0, 1, 2, 3, 55, 56, 57, 63, 64, 65,
            119, 120, 121, 127, 128, 129, 255, 256, 257,
            1_023, 1_024, 1_025,
        ]
        let chunkByteCounts = [1, 7, 55, 64, 65]

        for inputByteCount in inputByteCounts {
            let input = makeInput(byteCount: inputByteCount)
            let expected = boringSSLHash(input)
            precondition(
                SHA256.hash(data: input).elementsEqual(expected),
                "SHA-256 one-shot boundary validation failed"
            )
            precondition(
                SHA256.hash(bytes: input.span.bytes).elementsEqual(expected),
                "SHA-256 RawSpan boundary validation failed"
            )

            input.withUnsafeBytes { inputBytes in
                for chunkByteCount in chunkByteCounts {
                    var hasher = SHA256()
                    var offset = 0
                    while offset < inputBytes.count {
                        let end = min(offset + chunkByteCount, inputBytes.count)
                        hasher.update(bufferPointer: .init(rebasing: inputBytes[offset..<end]))
                        offset = end
                    }
                    precondition(
                        hasher.finalize().elementsEqual(expected),
                        "SHA-256 incremental boundary validation failed"
                    )
                }
            }

            let misalignedInput = makeInput(byteCount: inputByteCount + 1)
            validate(misalignedInput[1...])
        }
    }

    private static func boringSSLHash<Input: ContiguousBytes>(
        _ input: borrowing Input
    ) -> [UInt8] {
        input.withUnsafeBytes { boringSSLHash($0) }
    }

    private static func boringSSLHash(_ input: UnsafeRawBufferPointer) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        let succeeded = digest.withUnsafeMutableBytes { digestBytes in
            CCryptoBoringSSL_SHA256(
                input.baseAddress,
                input.count,
                digestBytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
            ) != nil
        }
        precondition(succeeded, "BoringSSL SHA-256 failed")
        return digest
    }

    private static func compare(
        operation: String,
        inputByteCount: Int,
        iterations: Int,
        isTargetGate: Bool,
        direct: (Int) -> UInt64,
        publicAPI: (Int) -> UInt64
    ) -> ComparisonResult {
        for _ in 0..<warmupCount {
            _ = direct(iterations)
            _ = publicAPI(iterations)
        }

        var directSamples: [Double] = []
        var publicSamples: [Double] = []
        var pairedRatios: [Double] = []
        var checksum: UInt64 = 0

        for sampleIndex in 0..<sampleCount {
            let directSample: Measurement
            let publicSample: Measurement
            if isTargetGate {
                (directSample, publicSample) = measureInterleavedPair(
                    iterations: iterations,
                    sampleIndex: sampleIndex,
                    direct: direct,
                    publicAPI: publicAPI
                )
            } else if sampleIndex.isMultiple(of: 2) {
                directSample = measure(iterations: iterations, operation: direct)
                publicSample = measure(iterations: iterations, operation: publicAPI)
            } else {
                publicSample = measure(iterations: iterations, operation: publicAPI)
                directSample = measure(iterations: iterations, operation: direct)
            }
            precondition(
                directSample.checksum == publicSample.checksum,
                "SHA-256 benchmark implementations produced different checksums"
            )
            let pairedRatio = publicSample.nanoseconds / directSample.nanoseconds
            directSamples.append(directSample.nanoseconds)
            publicSamples.append(publicSample.nanoseconds)
            pairedRatios.append(pairedRatio)
            checksum &+= directSample.checksum &+ publicSample.checksum
            print(
                [
                    "SAMPLE",
                    operation,
                    String(inputByteCount),
                    String(sampleIndex),
                    String(directSample.nanoseconds),
                    String(publicSample.nanoseconds),
                    String(pairedRatio),
                    String(directSample.checksum),
                    String(publicSample.checksum),
                ].joined(separator: ",")
            )
        }

        let directMedian = percentile(directSamples, percentile: 50)
        let publicMedian = percentile(publicSamples, percentile: 50)
        return ComparisonResult(
            operation: operation,
            inputByteCount: inputByteCount,
            iterations: iterations,
            directMedianNanoseconds: directMedian,
            publicMedianNanoseconds: publicMedian,
            pairedMedianRatio: percentile(pairedRatios, percentile: 50),
            pairedP90Ratio: percentile(pairedRatios, percentile: 90),
            isTargetGate: isTargetGate,
            checksum: checksum
        )
    }

    private static func measureInterleavedPair(
        iterations: Int,
        sampleIndex: Int,
        direct: (Int) -> UInt64,
        publicAPI: (Int) -> UInt64
    ) -> (direct: Measurement, publicAPI: Measurement) {
        var directNanoseconds = 0.0
        var publicNanoseconds = 0.0
        var directChecksum: UInt64 = 0
        var publicChecksum: UInt64 = 0

        for iterationIndex in 0..<iterations {
            let directFirst = (sampleIndex + iterationIndex).isMultiple(of: 2)
            if directFirst {
                let directMeasurement = measure(iterations: 1, operation: direct)
                directNanoseconds += directMeasurement.nanoseconds
                directChecksum &+= directMeasurement.checksum
                let publicMeasurement = measure(iterations: 1, operation: publicAPI)
                publicNanoseconds += publicMeasurement.nanoseconds
                publicChecksum &+= publicMeasurement.checksum
            } else {
                let publicMeasurement = measure(iterations: 1, operation: publicAPI)
                publicNanoseconds += publicMeasurement.nanoseconds
                publicChecksum &+= publicMeasurement.checksum
                let directMeasurement = measure(iterations: 1, operation: direct)
                directNanoseconds += directMeasurement.nanoseconds
                directChecksum &+= directMeasurement.checksum
            }
        }

        return (
            Measurement(nanoseconds: directNanoseconds, checksum: directChecksum),
            Measurement(nanoseconds: publicNanoseconds, checksum: publicChecksum)
        )
    }

    private static func measure(
        iterations: Int,
        operation: (Int) -> UInt64
    ) -> Measurement {
        #if os(WASI)
        let start = monotonicNanoseconds()
        let checksum = operation(iterations)
        return Measurement(nanoseconds: monotonicNanoseconds() - start, checksum: checksum)
        #else
        let clock = ContinuousClock()
        let start = clock.now
        let checksum = operation(iterations)
        let components = start.duration(to: clock.now).components
        let nanoseconds =
            Double(components.seconds) * 1_000_000_000
            + Double(components.attoseconds) / 1_000_000_000
        return Measurement(nanoseconds: nanoseconds, checksum: checksum)
        #endif
    }

    #if os(WASI)
    private static func monotonicNanoseconds() -> Double {
        var timestamp: __wasi_timestamp_t = 0
        let error = __wasi_clock_time_get(__wasi_clockid_t(1), 1, &timestamp)
        precondition(error == 0, "WASI monotonic clock is unavailable")
        return Double(timestamp)
    }
    #endif

    private static func percentile(_ samples: [Double], percentile: Int) -> Double {
        let sorted = samples.sorted()
        precondition(!sorted.isEmpty)
        let rank = max(1, (sorted.count * percentile + 99) / 100)
        return sorted[min(rank - 1, sorted.count - 1)]
    }

    private static func runCryptoOneShot(
        input: ArraySlice<UInt8>,
        iterations: Int
    ) -> UInt64 {
        var checksum: UInt64 = 0
        for iteration in 0..<iterations {
            checksum &+= consume(SHA256.hash(data: input)) &+ UInt64(iteration)
        }
        return checksum
    }

    private static func runCryptoRawSpanOneShot(
        input: ArraySlice<UInt8>,
        iterations: Int
    ) -> UInt64 {
        input.withUnsafeBytes { inputBytes in
            var checksum: UInt64 = 0
            for iteration in 0..<iterations {
                checksum &+= consume(SHA256.hash(bytes: inputBytes.bytes)) &+ UInt64(iteration)
            }
            return checksum
        }
    }

    private static func runCryptoIncremental(
        input: ArraySlice<UInt8>,
        iterations: Int,
        chunkByteCount: Int = 64
    ) -> UInt64 {
        input.withUnsafeBytes { inputBytes in
            var checksum: UInt64 = 0
            for iteration in 0..<iterations {
                var hasher = SHA256()
                var offset = 0
                while offset < inputBytes.count {
                    let end = min(offset + chunkByteCount, inputBytes.count)
                    hasher.update(bufferPointer: .init(rebasing: inputBytes[offset..<end]))
                    offset = end
                }
                checksum &+= consume(hasher.finalize()) &+ UInt64(iteration)
            }
            return checksum
        }
    }

    private static func runBoringSSLOneShot(
        input: ArraySlice<UInt8>,
        iterations: Int
    ) -> UInt64 {
        input.withUnsafeBytes { inputBytes in
            var checksum: UInt64 = 0
            for iteration in 0..<iterations {
                withUnsafeTemporaryAllocation(byteCount: Int(SHA256_DIGEST_LENGTH), alignment: 1) {
                    let result = CCryptoBoringSSL_SHA256(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                    precondition(result != nil, "BoringSSL SHA-256 failed")
                    checksum &+= consume($0) &+ UInt64(iteration)
                }
            }
            return checksum
        }
    }

    private static func runBoringSSLIncremental(
        input: ArraySlice<UInt8>,
        iterations: Int,
        chunkByteCount: Int = 64
    ) -> UInt64 {
        input.withUnsafeBytes { inputBytes in
            var checksum: UInt64 = 0
            for iteration in 0..<iterations {
                var state = SHA256_CTX()
                precondition(CCryptoBoringSSL_SHA256_Init(&state) == 1)
                var offset = 0
                while offset < inputBytes.count {
                    let end = min(offset + chunkByteCount, inputBytes.count)
                    let chunk = UnsafeRawBufferPointer(rebasing: inputBytes[offset..<end])
                    precondition(
                        CCryptoBoringSSL_SHA256_Update(&state, chunk.baseAddress, chunk.count) == 1
                    )
                    offset = end
                }
                withUnsafeTemporaryAllocation(byteCount: Int(SHA256_DIGEST_LENGTH), alignment: 1) {
                    precondition(
                        CCryptoBoringSSL_SHA256_Final(
                            $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            &state
                        ) == 1
                    )
                    checksum &+= consume($0) &+ UInt64(iteration)
                }
            }
            return checksum
        }
    }

    @inline(never)
    private static func consume<Bytes: ContiguousBytes>(_ bytes: borrowing Bytes) -> UInt64 {
        bytes.withUnsafeBytes { buffer in
            var checksum: UInt64 = 0xcbf2_9ce4_8422_2325
            for byte in buffer {
                checksum = (checksum ^ UInt64(byte)) &* 0x0000_0100_0000_01b3
            }
            return checksum
        }
    }
}

private struct Measurement {
    let nanoseconds: Double
    let checksum: UInt64
}

private struct ComparisonResult {
    let operation: String
    let inputByteCount: Int
    let iterations: Int
    let directMedianNanoseconds: Double
    let publicMedianNanoseconds: Double
    let pairedMedianRatio: Double
    let pairedP90Ratio: Double
    let isTargetGate: Bool
    let checksum: UInt64

    var csv: String {
        [
            "RESULT",
            operation,
            String(inputByteCount),
            String(iterations),
            String(directMedianNanoseconds),
            String(publicMedianNanoseconds),
            String(pairedMedianRatio),
            String(pairedP90Ratio),
            isTargetGate ? "yes" : "no",
        ].joined(separator: ",")
    }
}
