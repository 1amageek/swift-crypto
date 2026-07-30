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

#if canImport(Darwin) && !hasFeature(Embedded)
import Darwin

/// Provides scoped, in-place access to mutable state on Apple deployment targets
/// that predate `Synchronization.Mutex`.
///
/// The instance owns both the pthread mutex and `State`. Every read and mutation of
/// `State` must occur inside `withLock`; the closure cannot escape the borrowed value.
/// Destruction requires exclusive ownership and destroys the mutex exactly once.
package final class CryptoMutex<State>: @unchecked Sendable {
    private var mutex: pthread_mutex_t
    private var state: State

    package init(_ state: consuming State) {
        self.mutex = pthread_mutex_t()
        self.state = state
        precondition(pthread_mutex_init(&self.mutex, nil) == 0)
    }

    deinit {
        precondition(pthread_mutex_destroy(&self.mutex) == 0)
    }

    package func withLock<Result, Failure: Error>(
        _ body: (inout State) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        precondition(pthread_mutex_lock(&self.mutex) == 0)
        defer { precondition(pthread_mutex_unlock(&self.mutex) == 0) }
        return try body(&self.state)
    }
}
#else
import Synchronization

/// Uses the platform implementation supplied by Swift for WASM, Embedded, and
/// non-Apple native targets.
package struct CryptoMutex<State: ~Copyable>: ~Copyable, Sendable {
    private let storage: Mutex<State>

    package init(_ state: consuming sending State) {
        self.storage = Mutex(state)
    }

    package borrowing func withLock<Result, Failure: Error>(
        _ body: (inout sending State) throws(Failure) -> sending Result
    ) throws(Failure) -> sending Result {
        try self.storage.withLock(body)
    }
}
#endif
