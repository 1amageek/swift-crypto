//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 1amageek and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(WASI)

typealias ThreadOpsSystem = ThreadOpsWASI

enum ThreadOpsWASI: ThreadOps {
    final class ThreadSpecificKey {
        let destructor: ThreadSpecificKeyDestructor
        var value: UnsafeMutableRawPointer?

        init(destructor: @escaping ThreadSpecificKeyDestructor) {
            self.destructor = destructor
        }

        deinit {
            if let value {
                self.destructor(value)
            }
        }
    }

    typealias ThreadSpecificKeyDestructor = @convention(c) (UnsafeMutableRawPointer?) -> Void

    static func allocateThreadSpecificValue(destructor: @escaping ThreadSpecificKeyDestructor) -> ThreadSpecificKey {
        ThreadSpecificKey(destructor: destructor)
    }

    static func deallocateThreadSpecificValue(_ key: ThreadSpecificKey) {
        if let value = key.value {
            key.value = nil
            key.destructor(value)
        }
    }

    static func getThreadSpecificValue(_ key: ThreadSpecificKey) -> UnsafeMutableRawPointer? {
        key.value
    }

    static func setThreadSpecificValue(key: ThreadSpecificKey, value: UnsafeMutableRawPointer?) {
        key.value = value
    }
}

#endif
