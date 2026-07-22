# AGENTS.md

## Naming

- Name symbols after their cryptographic domain role, observable behavior, or ownership contract.
- Do not encode implementation mechanics, source language, calling convention, or compiler workaround in ordinary Swift symbol names.
- Do not use suffixes or qualifiers such as `Impl`, `Swift`, `C`, `CDecl`, or `Regular` to distinguish ordinary Swift implementations.
- Preserve an externally fixed C or ABI spelling only at the import, export, or callback boundary where that exact spelling is required.
- Translate boundary-specific spellings into domain names immediately after crossing the boundary.
- Name owned state and borrowed views distinctly when their lifetime or mutation contracts differ.
- Name tests after the behavior or invariant they verify, not after the implementation used to exercise it.

## Platform Contract

- Swift 6.4 is the only supported compiler language level.
- The supported Apple deployment targets are macOS 26, iOS 26, watchOS 26, tvOS 26, and visionOS 26 or newer.
- Linux, Android, Windows, standard WASI, true Embedded WASM, OpenBSD, and FreeBSD are supported non-Apple targets.
- Do not retain compatibility products, deprecated aliases, historical overloads, or compiler-version branches for unsupported toolchains.
- Express Apple deployment support in `Package.swift`; keep declaration-level availability only when an API requires a platform version newer than the package minimum.

## WASI Digest Validation

- Run `crypto-digest-validation` with the supported Swift WASI SDK after changing digest state ownership, copy-on-write, finalization, or zeroization.
- A successful build is insufficient; the executable must complete all known-vector and divergent-copy checks without trapping.
