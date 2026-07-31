# WASM and Embedded Support

## Baseline

The validated configuration is:

- Swift toolchain: `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a`
- Toolchain identifier: `org.swift.64202607231a`
- Swift compiler commit: `ef761e567dc94ee`
- Ordinary SDK: `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm`
- Embedded SDK: `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded`
- Target triple: `wasm32-unknown-wasip1`
- Embedded Unicode archive: `libswiftUnicodeDataTables.a` from the matching SDK
- Embedded C++ ABI: `libc++abi`

The package dependency on SwiftASN1 uses the fork URL and `main` branch. No release
manifest dependency uses a local path.

## Design authority

The implementation preserves Swift Crypto's existing contracts rather than replacing
its low-level owners with target-specific high-level containers.

| Area | Swift Crypto contract | Applied decision | Classification |
| --- | --- | --- | --- |
| Public API | Match CryptoKit-compatible representations and behavior | PEM support is available without weakening DER or raw representation checks | Compatible |
| Errors | Reject malformed input and preserve typed failures | Invalid DER remains an `ASN1Error`; invalid authenticated data remains a failure | Aligned |
| Ownership | C and C++ handles have one owner and one destruction path | EC keys, BIGNUM storage, digest contexts, and BN workspaces retain scoped borrows | Aligned |
| Concurrency | Mutable reusable backend state must be isolated | SHA-256 uses immutable-when-shared COW storage; mutable C contexts and `BN_CTX` workspaces use the same `Synchronization.Mutex<State>` owner and scoped mutation entry point on every target | Aligned |
| Lifetime | Buffer and pointer views must not escape their owner | Capability validation exercises borrowed slices and owned public-key duplication | Aligned |
| Compatibility | Use the oldest Apple releases that provide `Synchronization.Mutex`: macOS 15, iOS/tvOS 18, watchOS 11, and visionOS 2 | `CryptoMutex` is a package type alias for `Synchronization.Mutex` on every target; platform blocking behavior stays in the linked runtime implementation without imposing the unrelated Apple 26 baseline | Compatible |
| Performance | Avoid copies and hot-path adapter overhead | SHA-256 borrows full blocks directly; other synchronized backends retain the direct `Mutex` type-alias path | Aligned |
| Platform capability | Target conditions describe real API/runtime differences | Embedded uses its own allocation and typed-throws forms only where the baseline requires them | Compatible |
| Testing | Validate success, rejection, sharing, and runtime behavior | Native tests plus ordinary and Embedded runtime validators are required | Aligned |

## Shared-state review matrix

| Logical state | Target | Storage owner | Isolation | Read/mutation entry point | Release |
| --- | --- | --- | --- | --- | --- |
| SHA-256 context | Darwin with CryptoKit | CryptoKit implementation | CryptoKit contract | CryptoKit public API | CryptoKit owner |
| SHA-256 context | non-Darwin Native / WASM / Embedded | `SHA256State.Storage` COW owner | Shared backing is immutable; update first establishes uniqueness | `SHA256State.update` / `finalize` | state and inline partial buffer are zeroized in `deinit` |
| Other BoringSSL digest contexts | non-Darwin Native / WASM / Embedded | `Mutex<C context>` through `CryptoMutex` type alias | `Synchronization.Mutex` | `withLock` | locked zeroization, then owner release |
| Finite-field modulus and workspace | Native / WASM / Embedded | `Mutex<State>` through `CryptoMutex` type alias | `Synchronization.Mutex` | `withLock` | locked `BN_CTX_end` and `BN_CTX_free` |
| Prime-order curve runtime cache | Native / WASM / Embedded | `Mutex<Runtime?>` through type alias | `Synchronization.Mutex` | `withLock` | process-lifetime static owner |

No lock contains I/O, `await`, event emission, or an external callback. The
finite-field concurrency validator runs eight tasks against the same `BN_CTX` owner
and performs 512 operations before the owner is released.

## SHA-256 zero-copy and copy budget

The Pure Swift SHA-256 implementation uses the same source and ownership contract on
ordinary WASI and Embedded WASM. Its public state is a value whose backing storage is
immutable while shared. Mutation performs COW before entering the unsafe boundary.

| Path | Payload copies | SHA-256-owned heap allocations |
| --- | ---: | ---: |
| Contiguous one-shot / `RawSpan` full blocks | 0 | 0 |
| Incremental full blocks with a unique context | 0 | 1 COW owner |
| Fragment that completes a block | 1 copy into the inline 64-byte buffer | 1 COW owner |
| Final partial block | up to 63 buffered bytes copied into one padding block | 1 COW owner |
| Digest output | direct initialization of the 32-byte digest | 0 additional allocations |

Input pointers remain inside scoped borrows. Compression accepts only a proven
64-byte readable block, uses unaligned `UInt32` loads, and indexes the 16-word circular
schedule only with constants or a `15` mask. A completed partial block is compressed
directly from its inline buffer; it is not copied into another complete-block value.
The bounded final-tail copy preserves nonmutating, repeatable `finalize()` semantics.
Persistent state, the inline buffer, and finalization temporaries are cleared through
WASI `explicit_bzero`; a symbol audit of `SHA256State.o` contains no
`CCryptoBoringSSL_*` reference. The 16-word per-block message schedule remains a
transient stack value and is not explicitly wiped on every compression call.

## Unsafe and unchecked boundaries

The following existing patterns are intentional and were retained:

- `SecureBytes` is a value-semantic copy-on-write owner. Its shared empty backing is
  immutable through every reachable zero-length path; mutation first establishes a
  unique backing. The global `nonisolated(unsafe)` annotation avoids actor isolation
  for this immutable singleton and does not authorize unsynchronized mutation.
- BoringSSL key wrapper classes are `@unchecked Sendable` because each wrapper owns
  one independently allocated opaque key and releases it exactly once. Public-key
  extraction duplicates only the public point, so a public owner does not retain the
  private scalar.
- `ArbitraryPrecisionInteger` retains the upstream BIGNUM owner and scoped pointer
  closures. The support work does not widen pointer lifetime or expose pointers in a
  public API.
- Embedded `SecureBytes.Backing` owns its allocation, clears the full capacity, and
  deallocates exactly once. Borrowed spans are tied to the backing lifetime.

These annotations must not be removed solely to satisfy compiler checking. A future
change may replace one only if it preserves value semantics, pointer lifetime,
zeroization, deployment compatibility, and the measured hot path.

## Runtime coverage

The `crypto-capability-validation` executable validates:

- canonical Base64 decoding and malformed-input rejection;
- AES-CTR round trip and AES-GCM-SIV authenticated encryption failure behavior;
- malformed DER error identity;
- P-256 private and public PEM round trips;
- segmented HKDF, X9.63 key derivation, and HPKE;
- finite-field success, missing inverse, typed range failure, recovery after failure,
  and concurrent access to one arithmetic workspace;
- platform-sized secure storage and borrowed slice lifetime.

The following commands passed:

```bash
TOOLCHAINS=org.swift.64202607231a swift run -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  crypto-capability-validation

TOOLCHAINS=org.swift.64202607231a swift run -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  -Xlinker /path/to/libswiftUnicodeDataTables.a \
  -Xlinker -lc++abi \
  crypto-capability-validation
```

The Native finite-field unit suite passed with eight tests through `xcodebuild test`.
The Native capability executable also passed, including the concurrent
`Synchronization.Mutex` workspace path.

The production `SHA256State.swift` source was also compiled directly with the
Native AddressSanitizer and ThreadSanitizer. Both executions completed the
boundary differential tests, unaligned reads, output canaries, repeated
finalization, divergent COW copies, and 32 concurrent copies without a sanitizer
failure. The fixed ThreadSanitizer runtime emitted its known dyld module-map
warning, but produced no data-race report and exited successfully.

```bash
TOOLCHAINS=org.swift.64202607231a xcrun swiftc \
  -DCRYPTO_SHA256_STATE_STANDALONE_VALIDATION \
  -sanitize=address \
  Sources/Crypto/Util/Zeroization.swift \
  Sources/Crypto/Digests/SHA256State.swift \
  Validation/SHA256/SHA256StateSanitizerCommand.swift \
  -o /tmp/swift-crypto-sha256-asan

TOOLCHAINS=org.swift.64202607231a xcrun swiftc \
  -DCRYPTO_SHA256_STATE_STANDALONE_VALIDATION \
  -sanitize=thread \
  Sources/Crypto/Util/Zeroization.swift \
  Sources/Crypto/Digests/SHA256State.swift \
  Validation/SHA256/SHA256StateSanitizerCommand.swift \
  -o /tmp/swift-crypto-sha256-tsan
```

## Performance evidence

The performance executable is absent from the default manifest and normal test
schemes. Setting `SWIFT_CRYPTO_ENABLE_PERFORMANCE_VALIDATION=1` adds the opt-in
target, which compares the production Pure Swift public path with direct BoringSSL.
Each gated sample interleaves individual BoringSSL and Pure Swift hashes, alternates
their order, consumes all 32 digest bytes, and reports the median of 11 paired
elapsed-time ratios. The gate requires `public / BoringSSL <= 0.90909`, equivalent
to at least 1.10x throughput. Each target was run in three independent processes;
the table reports the median and full range of those three process medians.

| Target and operation | Median time ratio | Median speedup | Process speedup range | Gate |
| --- | ---: | ---: | ---: | --- |
| WASI, 1-MiB one-shot | 0.868557 | 1.151x | 1.150x...1.152x | 3/3 pass |
| WASI, 1-MiB `RawSpan` | 0.869198 | 1.150x | 1.147x...1.152x | 3/3 pass |
| WASI, 1-MiB incremental 64-byte chunks | 0.902079 | 1.109x | 1.104x...1.110x | 3/3 pass |
| WASI, unaligned 1-MiB + 1-byte `RawSpan` | 0.870601 | 1.149x | 1.148x...1.151x | 3/3 pass |
| Embedded WASM, 1-MiB one-shot | 0.867134 | 1.153x | 1.152x...1.154x | 3/3 pass |
| Embedded WASM, 1-MiB `RawSpan` | 0.866571 | 1.154x | 1.153x...1.157x | 3/3 pass |
| Embedded WASM, 1-MiB incremental 64-byte chunks | 0.863971 | 1.157x | 1.153x...1.159x | 3/3 pass |
| Embedded WASM, unaligned 1-MiB + 1-byte `RawSpan` | 0.866605 | 1.154x | 1.153x...1.154x | 3/3 pass |

The performance contract is sustained throughput at 1 MiB and 1 MiB + 1 byte.
The harness also reports 64/65-byte latency, 16-KiB throughput, unaligned input, and
7/55/65-byte fragmentation as diagnostics. On ordinary WASI, the 64-byte
`DataProtocol` one-shot path remains fixed-cost dominated; callers with an already
borrowed contiguous region should use the zero-copy `RawSpan` overload.
The BoringSSL reference is the vendored portable `OPENSSL_NO_ASM` WASI build, not
native assembly-enabled BoringSSL. All 42 gated process medians passed. Three
per-process nearest-rank p90 diagnostics over each set of 11 paired ratios do not
retain a 1.10x margin; they are not individual-hash latency percentiles.

The Native synchronization migration was measured separately because the SHA-256
benchmark does not enter `CryptoMutex`. Seven optimized samples performed five
million uncontended mutations through the previous pthread owner and
`Synchronization.Mutex`. The median changed from 49,476,959 ns to 21,746,416 ns,
a 56.0% reduction. Every sample checked the exact final mutation count. The
eight-task finite-field fixture separately validates the contended production path.

## Known platform exclusions

The following public CryptoExtras APIs are available to ordinary WASI but are
currently absent from Embedded module interfaces:

| Capability | Exclusion site | Current dependency | Completion condition |
| --- | --- | --- | --- |
| `P256._ARCV1` and `P384._ARCV1` credential APIs | `Sources/CryptoExtras/ARC/*.swift` | The ARC implementation is enclosed by `#if !hasFeature(Embedded)` and still imports Foundation-backed representation types. | Remove the source-group exclusion, preserve the bounded representation and typed-error contracts, and run issuance, presentation, malformed-representation, and concurrency fixtures on Embedded WASM. |
| `_RSA.Signing.PrivateKey.PassphraseCallback`, `PassphraseSetter`, and encrypted-PEM initialization | `Sources/CryptoExtras/RSA/RSA.swift`, `RSA_boring.swift`, and `BoringSSLPassphraseCallbackManager.swift` | The C callback bridge retains a Swift protocol existential through `Unmanaged` while BoringSSL synchronously invokes the callback. | Implement a verified Embedded owner/lease bridge with exactly-once retention and typed callback failure, then test success, thrown callback errors, oversized passphrases, and owner release on Embedded WASM. |
| `BoringSSLAEAD.AEADContext.init<Key: ContiguousBytes>` | `Sources/CryptoBoringWrapper/AEAD/BoringSSLAEAD.swift` | Embedded currently exposes only the `RawSpan` initializer used by package call sites. | Restore the generic public initializer without materializing key bytes and validate success plus unsupported key-size failures on Embedded WASM. |
| `CustomStringConvertible` on `Digest` and `MessageAuthenticationCode`, plus digest, MAC, and `SharedSecret` descriptions | `Sources/Crypto/Digests`, `Sources/Crypto/Message Authentication Codes`, and `Sources/Crypto/Key Agreement/DH.swift` | Embedded currently excludes the hex-string presentation layer and weakens these protocol refinements while retaining all cryptographic byte operations. | Provide a non-Foundation hexadecimal formatter, restore identical protocol refinements, and compare ordinary and Embedded module interfaces and rendered values. |

These are absent declarations, not callable success stubs. They remain capability
gaps until the complete ownership, error, and target-runtime contracts above are
implemented and validated. They must not be exposed through placeholder results.

The Native `SHA512256DigestTests` XCTest bundle compiled, but Xcode 27 beta
`xctest` stopped before bundle loading completed. Two runs with independent
DerivedData directories remained in `NSBundle` -> `_CFIterateDirectory` ->
`opendir`; no test method or package implementation was entered. This result is
recorded as not executed, not passed. The same production SHA-512/256 path passed
the ordinary WASI and Embedded WASM capability executables.
