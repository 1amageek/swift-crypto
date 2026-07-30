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

internal import CCryptoBoringSSL

/// Owns the modulus and reusable arithmetic workspace for finite-field operations.
///
/// BoringSSL mutates `BN_CTX` while an operation is running. Keeping the modulus and
/// workspace in one mutex makes every borrow scoped and prevents the workspace pointer
/// from escaping into unsynchronized callers.
@usableFromInline
package final class FiniteFieldArithmeticContext: Sendable {
    private struct State {
        let modulus: ArbitraryPrecisionInteger
        let workspace: OpaquePointer
    }

    private let state: CryptoMutex<State>

    @usableFromInline
    package init(modulus: ArbitraryPrecisionInteger) throws(CryptoBoringWrapperError) {
        guard let workspace = CCryptoBoringSSL_BN_CTX_new() else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        CCryptoBoringSSL_BN_CTX_start(workspace)
        self.state = CryptoMutex(State(modulus: modulus, workspace: workspace))
    }

    deinit {
        state.withLock { state in
            CCryptoBoringSSL_BN_CTX_end(state.workspace)
            CCryptoBoringSSL_BN_CTX_free(state.workspace)
        }
    }

    /// Borrows the arithmetic workspace for one complete BoringSSL operation.
    ///
    /// The operation must not call another method on this context because `Mutex` is
    /// intentionally non-recursive.
    @usableFromInline
    package func performWithArithmeticWorkspace(
        _ operation: (OpaquePointer) -> Int32
    ) -> Int32 {
        state.withLock { state in
            operation(state.workspace)
        }
    }
}

// MARK: - Arithmetic operations

extension FiniteFieldArithmeticContext {
    @usableFromInline
    package func residue(
        _ value: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let returnCode = state.withLock { state in
            value.withUnsafeBignumPointer { valuePointer in
                state.modulus.withUnsafeBignumPointer { modulusPointer in
                    result.withUnsafeMutableBignumPointer { resultPointer in
                        CCryptoBoringSSL_BN_nnmod(
                            resultPointer,
                            valuePointer,
                            modulusPointer,
                            state.workspace
                        )
                    }
                }
            }
        }

        guard returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package func square(
        _ value: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let returnCode = state.withLock { state in
            value.withUnsafeBignumPointer { valuePointer in
                state.modulus.withUnsafeBignumPointer { modulusPointer in
                    result.withUnsafeMutableBignumPointer { resultPointer in
                        CCryptoBoringSSL_BN_mod_sqr(
                            resultPointer,
                            valuePointer,
                            modulusPointer,
                            state.workspace
                        )
                    }
                }
            }
        }

        guard returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package func multiply(
        _ lhs: ArbitraryPrecisionInteger,
        _ rhs: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let returnCode = state.withLock { state in
            lhs.withUnsafeBignumPointer { lhsPointer in
                rhs.withUnsafeBignumPointer { rhsPointer in
                    state.modulus.withUnsafeBignumPointer { modulusPointer in
                        result.withUnsafeMutableBignumPointer { resultPointer in
                            CCryptoBoringSSL_BN_mod_mul(
                                resultPointer,
                                lhsPointer,
                                rhsPointer,
                                modulusPointer,
                                state.workspace
                            )
                        }
                    }
                }
            }
        }

        guard returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package func add(
        _ lhs: ArbitraryPrecisionInteger,
        _ rhs: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let returnCode = state.withLock { state in
            lhs.withUnsafeBignumPointer { lhsPointer in
                rhs.withUnsafeBignumPointer { rhsPointer in
                    state.modulus.withUnsafeBignumPointer { modulusPointer in
                        result.withUnsafeMutableBignumPointer { resultPointer in
                            CCryptoBoringSSL_BN_mod_add(
                                resultPointer,
                                lhsPointer,
                                rhsPointer,
                                modulusPointer,
                                state.workspace
                            )
                        }
                    }
                }
            }
        }

        guard returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package func subtract(
        _ value: ArbitraryPrecisionInteger,
        from minuend: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let returnCode = state.withLock { state in
            value.withUnsafeBignumPointer { valuePointer in
                minuend.withUnsafeBignumPointer { minuendPointer in
                    state.modulus.withUnsafeBignumPointer { modulusPointer in
                        result.withUnsafeMutableBignumPointer { resultPointer in
                            CCryptoBoringSSL_BN_mod_sub(
                                resultPointer,
                                minuendPointer,
                                valuePointer,
                                modulusPointer,
                                state.workspace
                            )
                        }
                    }
                }
            }
        }

        guard returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package func positiveSquareRoot(
        _ value: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        let resultPointer = state.withLock { state in
            value.withUnsafeBignumPointer { valuePointer in
                state.modulus.withUnsafeBignumPointer { modulusPointer in
                    CCryptoBoringSSL_BN_mod_sqrt(
                        nil,
                        valuePointer,
                        modulusPointer,
                        state.workspace
                    )
                }
            }
        }

        guard let resultPointer else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        defer {
            CCryptoBoringSSL_BN_free(resultPointer)
        }
        return try ArbitraryPrecisionInteger(copying: resultPointer)
    }

    @usableFromInline
    package func inverse(
        _ value: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger? {
        var result = ArbitraryPrecisionInteger()
        let outcome = state.withLock { state -> (succeeded: Bool, errorCode: UInt32) in
            CCryptoBoringSSL_ERR_clear_error()
            let resultPointer = result.withUnsafeMutableBignumPointer { resultPointer in
                value.withUnsafeBignumPointer { valuePointer in
                    state.modulus.withUnsafeBignumPointer { modulusPointer in
                        CCryptoBoringSSL_BN_mod_inverse(
                            resultPointer,
                            valuePointer,
                            modulusPointer,
                            state.workspace
                        )
                    }
                }
            }
            guard resultPointer == nil else {
                return (true, 0)
            }
            return (false, CCryptoBoringSSL_ERR_get_error())
        }

        if outcome.succeeded {
            return result
        }
        if CCryptoBoringSSL_ERR_GET_REASON(outcome.errorCode) == BN_R_NO_INVERSE {
            return nil
        }
        throw CryptoBoringWrapperError.underlyingCoreCryptoError(
            error: Int32(bitPattern: outcome.errorCode)
        )
    }

    @usableFromInline
    package func pow(
        _ base: ArbitraryPrecisionInteger,
        _ exponent: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        try pow(base, exponent, mode: .general)
    }

    @usableFromInline
    package func pow(
        secret base: ArbitraryPrecisionInteger,
        _ exponent: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        guard contains(base) else {
            throw CryptoBoringWrapperError.incorrectParameterSize
        }
        return try pow(base, exponent, mode: .montgomery)
    }

    @usableFromInline
    package func pow(
        secret base: ArbitraryPrecisionInteger,
        secret exponent: ArbitraryPrecisionInteger
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        guard contains(base) else {
            throw CryptoBoringWrapperError.incorrectParameterSize
        }
        return try pow(base, exponent, mode: .constantTimeMontgomery)
    }

    private func contains(_ value: ArbitraryPrecisionInteger) -> Bool {
        state.withLock { state in
            value < state.modulus
        }
    }

    private enum ExponentiationMode {
        case general
        case montgomery
        case constantTimeMontgomery
    }

    private func pow(
        _ base: ArbitraryPrecisionInteger,
        _ exponent: ArbitraryPrecisionInteger,
        mode: ExponentiationMode
    ) throws(CryptoBoringWrapperError) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let outcome = state.withLock { state -> (returnCode: Int32, allocationFailed: Bool) in
            result.withUnsafeMutableBignumPointer { resultPointer in
                base.withUnsafeBignumPointer { basePointer in
                    exponent.withUnsafeBignumPointer { exponentPointer in
                        state.modulus.withUnsafeBignumPointer { modulusPointer in
                            if case .general = mode {
                                return (
                                    CCryptoBoringSSL_BN_mod_exp(
                                        resultPointer,
                                        basePointer,
                                        exponentPointer,
                                        modulusPointer,
                                        state.workspace
                                    ),
                                    false
                                )
                            }

                            guard let montgomeryContext =
                                CCryptoBoringSSL_BN_MONT_CTX_new_for_modulus(
                                    modulusPointer,
                                    state.workspace
                                )
                            else {
                                return (0, true)
                            }
                            defer {
                                CCryptoBoringSSL_BN_MONT_CTX_free(montgomeryContext)
                            }
                            let returnCode: Int32
                            switch mode {
                            case .general:
                                preconditionFailure("General exponentiation does not use a Montgomery context")
                            case .montgomery:
                                returnCode = CCryptoBoringSSL_BN_mod_exp_mont(
                                    resultPointer,
                                    basePointer,
                                    exponentPointer,
                                    modulusPointer,
                                    state.workspace,
                                    montgomeryContext
                                )
                            case .constantTimeMontgomery:
                                returnCode = CCryptoBoringSSL_BN_mod_exp_mont_consttime(
                                    resultPointer,
                                    basePointer,
                                    exponentPointer,
                                    modulusPointer,
                                    state.workspace,
                                    montgomeryContext
                                )
                            }
                            return (
                                returnCode,
                                false
                            )
                        }
                    }
                }
            }
        }

        guard !outcome.allocationFailed, outcome.returnCode == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }
}
