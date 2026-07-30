//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#else
#error("Unsupported platform")
#endif

let help = """
Usage: crypto-shasum [OPTION]... [FILE]...
Print SHA checksums.
With no FILE, or when FILE is -, read standard input.

  -a, --algorithm   256 (default), 384, 512
"""

enum ShasumError: Error, CustomStringConvertible {
    case unableToOpen(path: String, errorCode: CInt)
    case unableToRead(name: String, errorCode: CInt)
    case unableToReadArguments(errorCode: UInt16)

    var description: String {
        switch self {
        case .unableToOpen(let path, let errorCode):
            return "Unable to open \(path) (errno \(errorCode))"
        case .unableToRead(let name, let errorCode):
            return "Unable to read \(name) (errno \(errorCode))"
        case .unableToReadArguments(let errorCode):
            return "Unable to read command-line arguments (WASI errno \(errorCode))"
        }
    }
}

struct InputFile {
    let name: String
    let descriptor: CInt
    let shouldClose: Bool

    static var standardInput: Self {
        Self(name: "-", descriptor: STDIN_FILENO, shouldClose: false)
    }

    static func open(path: String) throws -> Self {
        let descriptor = path.withCString { pathPointer in
            systemOpen(pathPointer)
        }
        guard descriptor >= 0 else {
            throw ShasumError.unableToOpen(path: path, errorCode: errno)
        }
        return Self(name: path, descriptor: descriptor, shouldClose: true)
    }

    func closeIfNeeded() {
        if self.shouldClose {
            _ = close(self.descriptor)
        }
    }
}

@inline(__always)
private func systemOpen(_ path: UnsafePointer<CChar>) -> CInt {
    open(path, O_RDONLY)
}

enum SupportedHashFunction {
    case sha256
    case sha384
    case sha512

    init?(commandLineFlag flag: String) {
        switch flag {
        case "256":
            self = .sha256
        case "384":
            self = .sha384
        case "512":
            self = .sha512
        default:
            return nil
        }
    }

    func hashLoop(from input: InputFile) throws -> [UInt8] {
        switch self {
        case .sha256:
            return Array(try Self.hashLoop(from: input, with: SHA256.self))
        case .sha384:
            return Array(try Self.hashLoop(from: input, with: SHA384.self))
        case .sha512:
            return Array(try Self.hashLoop(from: input, with: SHA512.self))
        }
    }

    private static let readSize = 8192

    private static func hashLoop<HF: HashFunction>(from input: InputFile, with hasher: HF.Type) throws -> HF.Digest {
        var hasher = HF()
        var buffer = [UInt8](repeating: 0, count: Self.readSize)

        while true {
            let byteCount = buffer.withUnsafeMutableBytes { bytes in
                read(input.descriptor, bytes.baseAddress, bytes.count)
            }
            if byteCount == 0 {
                break
            }
            if byteCount < 0 {
                if errno == EINTR {
                    continue
                }
                throw ShasumError.unableToRead(name: input.name, errorCode: errno)
            }

            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<byteCount]))
            }
        }

        return hasher.finalize()
    }
}

extension String {
    init(hexEncoding bytes: [UInt8]) {
        let digits = Array("0123456789abcdef".utf8)
        var encodedBytes: [UInt8] = []
        encodedBytes.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            encodedBytes.append(digits[Int(byte >> 4)])
            encodedBytes.append(digits[Int(byte & 0x0f)])
        }
        self.init(decoding: encodedBytes, as: UTF8.self)
    }
}

func processInputs(_ inputs: [InputFile], algorithm: SupportedHashFunction) throws {
    for input in inputs {
        defer { input.closeIfNeeded() }
        let result = try algorithm.hashLoop(from: input)
        print("\(String(hexEncoding: result))  \(input.name)")
    }
}

private func commandLineArguments() throws -> [String] {
    #if hasFeature(Embedded) && os(WASI)
    var argumentCount: UInt = 0
    var bufferSize: UInt = 0
    let sizesError = __wasi_args_sizes_get(&argumentCount, &bufferSize)
    guard sizesError == 0 else {
        throw ShasumError.unableToReadArguments(errorCode: sizesError)
    }

    var argumentPointers = [UnsafeMutablePointer<UInt8>?](
        repeating: nil,
        count: max(1, Int(argumentCount))
    )
    var argumentBuffer = [UInt8](repeating: 0, count: max(1, Int(bufferSize)))
    let argumentsError = argumentPointers.withUnsafeMutableBufferPointer { pointers in
        argumentBuffer.withUnsafeMutableBufferPointer { buffer in
            __wasi_args_get(pointers.baseAddress!, buffer.baseAddress!)
        }
    }
    guard argumentsError == 0 else {
        throw ShasumError.unableToReadArguments(errorCode: argumentsError)
    }

    var arguments: [String] = []
    arguments.reserveCapacity(Int(argumentCount))
    for index in 0..<Int(argumentCount) {
        guard let start = argumentPointers[index] else {
            continue
        }
        var end = start
        while end.pointee != 0 {
            end += 1
        }
        arguments.append(String(decoding: UnsafeBufferPointer(start: start, count: start.distance(to: end)), as: UTF8.self))
    }
    return arguments
    #else
    return CommandLine.arguments
    #endif
}

func main() throws {
    var arguments = try commandLineArguments().dropFirst()
    var algorithm = SupportedHashFunction.sha256
    var inputs: [InputFile] = []

    flagsLoop: while let first = arguments.first, first.starts(with: "-") {
        arguments = arguments.dropFirst()

        switch first {
        case "-a", "--algorithm":
            guard let flag = arguments.popFirst(), let newAlgorithm = SupportedHashFunction(commandLineFlag: flag) else {
                print("Unknown algorithm description.")
                return
            }
            algorithm = newAlgorithm

        case "--":
            break flagsLoop

        case "-":
            inputs.append(.standardInput)
            break flagsLoop

        default:
            print(help)
            return
        }
    }

    while let first = arguments.popFirst() {
        inputs.append(try .open(path: first))
    }

    if inputs.isEmpty {
        inputs.append(.standardInput)
    }

    try processInputs(inputs, algorithm: algorithm)
}

do {
    try main()
} catch let error as ShasumError {
    print(error.description)
    exit(EXIT_FAILURE)
} catch {
    print("Unexpected crypto-shasum failure")
    exit(EXIT_FAILURE)
}
