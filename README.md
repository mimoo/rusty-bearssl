# bearssl-rs

An idiomatic Rust reimplementation of [BearSSL](https://bearssl.org/), interoperable with the original C library.

> ⚠️ **This is an LLM-driven port.** The entire crate was produced by Claude Code
> (Anthropic) via multi-agent orchestration — translating Thomas Pornin's C
> source to Rust file-by-file. It has **not** been written or independently
> reviewed by a human cryptographer, and has **not** undergone a security audit.
> Do not use it in production or where security matters. It exists as an
> experiment in LLM-driven porting and as a faithful, readable Rust mirror of
> BearSSL for study.

## What it is

A line-faithful port that deliberately mirrors BearSSL:

- **Same layout** — `src/` mirrors BearSSL's `src/` directory file-for-file
  (`codec/`, `hash/`, `mac/`, `kdf/`, `rand/`, `int/`, `symcipher/`, `rsa/`,
  `ec/`, `aead/`, `x509/`, `ssl/`).
- **Same identifiers and algorithms** — C names (`br_sha256_init`, `br_rsa_i31_*`,
  the constant-time `MUX`/`EQ`/`GT` primitives, …) are preserved verbatim for
  traceability; algorithms and constants are copied, not reinvented.
- **Idiomatic where it's free** — the C OOP vtables become descriptor structs +
  trait objects; raw pointer+length pairs become slices; modular arithmetic uses
  explicit `wrapping_*`. Behavior is unchanged.

See [`CONVENTIONS.md`](CONVENTIONS.md) for the porting rules.

## Status

| | |
|---|---|
| Coverage | ~100% of BearSSL's *distinct* functionality |
| Tests | 135 passing, 0 failures, 0 warnings |
| Interop | live TLS 1.2 handshakes against the upstream C `brssl`, both directions + mutual TLS |

**Verified live against C BearSSL** (`brssl`): Rust client ↔ C server and Rust
server ↔ C client, for ECDHE-RSA and RSA key exchange with AES-GCM,
AES-CBC-SHA256, and ChaCha20-Poly1305, plus mutual (client-cert) authentication.

**Implemented & tested** (against BearSSL's own + standard FIPS/NIST/RFC vectors):
MD5/SHA-1/SHA-2, SHAKE/SHA-3, HMAC + constant-time HMAC, HKDF; big-integer math;
AES (constant-time) / ChaCha20 / Poly1305 / DES-3DES; GCM, CCM, EAX; RSA
(PKCS#1 v1.5, PSS, OAEP, keygen); EC (P-256/384/521, X25519, ECDSA, keygen);
HMAC-DRBG and AES-CTR-DRBG; X.509 chain validation, PEM codec, DER key encoding;
and the full TLS 1.2 engine (client, server, mutual TLS, session cache, the
GCM/CBC/CCM/ChaCha20-Poly1305 record layers, and the blocking I/O wrapper).

**Deferred by design** (not functional gaps): BearSSL's interchangeable
*identical-result* alternates — the `i15`/`i32`/`i62` big-integer RSA & EC
families and the hardware/SIMD variants (AES-NI, POWER8, SSE2, PCLMUL GHASH) —
since one member of each family is ported and produces the same output. The one
remaining narrow case is static-ECDH client authentication.

## Usage

```sh
cargo test                 # unit + KAT suite
# live interop tests (require a built BearSSL checkout with build/brssl):
BRSSL_DIR=/path/to/BearSSL cargo test
```

## License

MIT, same as upstream BearSSL. The original copyright
(`Copyright (c) Thomas Pornin`) is retained in every ported file; see
`LICENSE.txt`.
