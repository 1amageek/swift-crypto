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

@_exported import Synchronization

/// Uses one scoped synchronization and ownership contract on every supported target.
///
/// Target-specific blocking behavior belongs to the platform implementation used by
/// `Synchronization.Mutex`, not to the cryptographic state owners in this package.
package typealias CryptoMutex<State: ~Copyable> = Mutex<State>
