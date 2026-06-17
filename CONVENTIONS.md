# BearSSL → Rust porting conventions

Goal: a faithful, interoperable reimplementation of BearSSL in Rust. Same
algorithms, same file/folder layout, same identifier names as the C source,
with idiomatic Rust used only where it does not change behavior.

## Layout

The crate mirrors `BearSSL/src/` exactly:

```
BearSSL/src/codec/dec32be.c   ->   bearssl-rs/src/codec/dec32be.rs
BearSSL/src/hash/sha2small.c  ->   bearssl-rs/src/hash/sha2small.rs
BearSSL/src/inner.h           ->   bearssl-rs/src/inner.rs   (shared inlines + CT prims)
BearSSL/inc/bearssl_hash.h    ->   public types/consts re-exported from the matching module
```

Each C source file becomes a Rust file of the same stem. Each directory has a
`mod.rs` declaring its files. `lib.rs` declares the top-level modules.

## Naming

- Keep BearSSL's C identifiers verbatim: `br_sha256_init`, `br_dec32be`,
  `br_md5_round`, struct fields (`val`, `count`, `buf`), constants (`br_md5_IV`).
  This is required for traceability and review against the C source.
- This means we deliberately keep `snake_case` function names that already match
  Rust style, and silence `non_upper_case_globals` / `non_camel_case_types` where
  C constants/structs force it (see `#![allow(...)]` in lib.rs).
- Macros (`MUX`, `EQ`, `GT`, `MUL31`, ...) become `#[inline(always)]` fns with the
  same UPPERCASE name; allow `non_snake_case` on them.

## Types

- `unsigned char *` buffers -> `&[u8]` / `&mut [u8]`. Reads/writes that the C code
  bounds by an explicit length use the slice length or an explicit subslice.
- `uint32_t`/`uint64_t`/`size_t` -> `u32`/`u64`/`usize`. Preserve exact widths;
  wrapping arithmetic must use `wrapping_*` / `Wrapping` to match C modular semantics.
- Right shifts of values that C treats as signed (`ARSH`) use `i32`/`i64` casts.
- The OOP vtables (`br_hash_class`, `br_block_cbcenc_class`, ...) are represented
  with a Rust `struct` of `fn` pointers named identically, so the C control flow and
  function-table dispatch are preserved. Idiomatic trait wrappers may be layered on
  top later but must not replace the vtable.

## Constant-time

Constant-time primitives in `inner.rs` (`NOT/MUX/EQ/NEQ/GT/...`) are ported bit for
bit. Do NOT "simplify" them with branches or standard-library comparisons.

## Tests

- Per-module unit tests use the official BearSSL test vectors (from
  `BearSSL/test/test_crypto.c`) embedded as hex.
- `tests/interop/` cross-checks outputs against the C library / `brssl` CLI.
- Target: 100% interoperability.

## Copyright

Preserve the MIT license header (Thomas Pornin) at the top of every ported file.
