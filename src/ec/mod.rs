/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Elliptic curves and ECDSA (`src/ec/`).
//!
//! Mirrors BearSSL's `src/ec/` directory. The C OOP vtable `br_ec_impl` is
//! modelled as a Rust `struct` of `fn` pointers with the same fields
//! (`supported_curves`, `generator`, `order`, `xoff`, `mul`, `mulgen`,
//! `muladd`), exactly as elsewhere in the crate, so the function-table dispatch
//! is preserved. The ECDSA signer/verifier function-pointer typedefs
//! (`br_ecdsa_sign`, `br_ecdsa_vrfy`) are plain `pub type` aliases, with the
//! `br_ecdsa_i31_*` functions as concrete instances.
//!
//! Ported implementations:
//!
//! * [`br_ec_prime_i31`] — generic prime curves (P-256/P-384/P-521) over the
//!   `i31` modular-integer code.
//! * [`br_ec_p256_m31`] — specialised P-256 using 31-bit multiplications.
//! * [`br_ec_c25519_i31`] — Curve25519 / X25519 over the `i31` code.
//!
//! Identical-result alternates from the C source are deferred (not ported):
//! all `*_i15`, `*_m15`, `*_m62`, `*_m64` variants, `br_ec_all_m15`, and the
//! ECDSA `i15` variants. [`br_ec_all_m31`] and [`br_ec_get_default`] are
//! provided and route to the ported portable implementations.

use crate::hash::br_hash_class;

// ---- curve identifiers (inc/bearssl_ec.h) -----------------------------------

pub const BR_EC_sect163k1: i32 = 1;
pub const BR_EC_sect163r1: i32 = 2;
pub const BR_EC_sect163r2: i32 = 3;
pub const BR_EC_sect193r1: i32 = 4;
pub const BR_EC_sect193r2: i32 = 5;
pub const BR_EC_sect233k1: i32 = 6;
pub const BR_EC_sect233r1: i32 = 7;
pub const BR_EC_sect239k1: i32 = 8;
pub const BR_EC_sect283k1: i32 = 9;
pub const BR_EC_sect283r1: i32 = 10;
pub const BR_EC_sect409k1: i32 = 11;
pub const BR_EC_sect409r1: i32 = 12;
pub const BR_EC_sect571k1: i32 = 13;
pub const BR_EC_sect571r1: i32 = 14;
pub const BR_EC_secp160k1: i32 = 15;
pub const BR_EC_secp160r1: i32 = 16;
pub const BR_EC_secp160r2: i32 = 17;
pub const BR_EC_secp192k1: i32 = 18;
pub const BR_EC_secp192r1: i32 = 19;
pub const BR_EC_secp224k1: i32 = 20;
pub const BR_EC_secp224r1: i32 = 21;
pub const BR_EC_secp256k1: i32 = 22;
pub const BR_EC_secp256r1: i32 = 23;
pub const BR_EC_secp384r1: i32 = 24;
pub const BR_EC_secp521r1: i32 = 25;
pub const BR_EC_brainpoolP256r1: i32 = 26;
pub const BR_EC_brainpoolP384r1: i32 = 27;
pub const BR_EC_brainpoolP512r1: i32 = 28;
pub const BR_EC_curve25519: i32 = 29;
pub const BR_EC_curve448: i32 = 30;

/// Largest curve size, in bits (`BR_MAX_EC_SIZE` from inner.h).
pub const BR_MAX_EC_SIZE: usize = 528;

/// Maximum size for an EC private key element buffer (`BR_EC_KBUF_PRIV_MAX_SIZE`).
pub const BR_EC_KBUF_PRIV_MAX_SIZE: usize = 72;
/// Maximum size for an EC public key element buffer (`BR_EC_KBUF_PUB_MAX_SIZE`).
pub const BR_EC_KBUF_PUB_MAX_SIZE: usize = 145;

// ---- public/private key structures (inc/bearssl_ec.h) -----------------------

/// EC public key (`br_ec_public_key`). `q` holds the uncompressed point.
pub struct br_ec_public_key<'a> {
    pub curve: i32,
    pub q: &'a [u8],
}

/// EC private key (`br_ec_private_key`). `x` is the scalar (big-endian).
pub struct br_ec_private_key<'a> {
    pub curve: i32,
    pub x: &'a [u8],
}

// ---- generic curve parameters (inner.h: br_ec_curve_def) --------------------

/// Generic EC parameters: curve order (unsigned big-endian) and encoded
/// conventional generator. Mirrors `br_ec_curve_def`.
pub struct br_ec_curve_def {
    pub curve: i32,
    pub order: &'static [u8],
    pub generator: &'static [u8],
}

// ---- the EC implementation vtable (inc/bearssl_ec.h: br_ec_impl) ------------

/// An EC implementation (`br_ec_impl`): a 32-bit `supported_curves` bitfield
/// plus the seven method function pointers. The signatures mirror the C ones,
/// with `unsigned char *` buffers becoming byte slices.
pub struct br_ec_impl {
    /// Bitfield of supported curve IDs (bit `x` set => curve `x` supported).
    pub supported_curves: u32,
    /// Conventional generator (encoded point) for the curve.
    pub generator: fn(curve: i32) -> &'static [u8],
    /// Subgroup order (unsigned big-endian) for the curve.
    pub order: fn(curve: i32) -> &'static [u8],
    /// Offset and length of the X coordinate in an encoded point; returns the
    /// offset and writes the length through `len`.
    pub xoff: fn(curve: i32, len: &mut usize) -> usize,
    /// Multiply the point in `G` by `x`; result written over `G`. Returns 1 on
    /// success, 0 on error.
    pub mul: fn(G: &mut [u8], x: &[u8], curve: i32) -> u32,
    /// Multiply the generator by `x`; writes the encoded point into `R` and
    /// returns its length.
    pub mulgen: fn(R: &mut [u8], x: &[u8], curve: i32) -> usize,
    /// Compute `x*A + y*B` (or `x*A + y*G` if `B` is `None`); result over `A`.
    /// Returns 1 on success, 0 on error.
    pub muladd: fn(A: &mut [u8], B: Option<&[u8]>, x: &[u8], y: &[u8], curve: i32) -> u32,
}

// ---- ECDSA function-pointer typedefs (inc/bearssl_ec.h) ---------------------

/// ECDSA signer function type (`br_ecdsa_sign`).
pub type br_ecdsa_sign = fn(
    impl_: &br_ec_impl,
    hf: &'static br_hash_class,
    hash_value: &[u8],
    sk: &br_ec_private_key,
    sig: &mut [u8],
) -> usize;

/// ECDSA verifier function type (`br_ecdsa_vrfy`).
pub type br_ecdsa_vrfy = fn(
    impl_: &br_ec_impl,
    hash: &[u8],
    pk: &br_ec_public_key,
    sig: &[u8],
) -> u32;

// ---- submodules -------------------------------------------------------------

mod ec_curve25519;
mod ec_secp256r1;
mod ec_secp384r1;
mod ec_secp521r1;

mod ec_prime_i31;
mod ec_p256_m31;
mod ec_c25519_i31;

mod ecdsa_atr;
mod ecdsa_i31_bits;
mod ecdsa_i31_sign_asn1;
mod ecdsa_i31_sign_raw;
mod ecdsa_i31_vrfy_asn1;
mod ecdsa_i31_vrfy_raw;
mod ecdsa_rta;

mod ec_default;
mod ec_keygen;
mod ec_pubkey;

// ---- re-exports -------------------------------------------------------------

pub use ec_curve25519::br_curve25519;
pub use ec_secp256r1::br_secp256r1;
pub use ec_secp384r1::br_secp384r1;
pub use ec_secp521r1::br_secp521r1;

pub use ec_prime_i31::br_ec_prime_i31;
pub use ec_p256_m31::br_ec_p256_m31;
pub use ec_c25519_i31::br_ec_c25519_i31;

pub use ec_default::{br_ec_all_m31, br_ec_get_default};
pub use ec_keygen::br_ec_keygen;
pub use ec_pubkey::br_ec_compute_pub;

pub use ecdsa_atr::br_ecdsa_asn1_to_raw;
pub use ecdsa_i31_bits::br_ecdsa_i31_bits2int;
pub use ecdsa_i31_sign_asn1::br_ecdsa_i31_sign_asn1;
pub use ecdsa_i31_sign_raw::br_ecdsa_i31_sign_raw;
pub use ecdsa_i31_vrfy_asn1::br_ecdsa_i31_vrfy_asn1;
pub use ecdsa_i31_vrfy_raw::br_ecdsa_i31_vrfy_raw;
pub use ecdsa_rta::br_ecdsa_raw_to_asn1;
