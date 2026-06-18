/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! RSA (`src/rsa/`).
//!
//! Mirrors BearSSL's `src/rsa/` directory. BearSSL provides four parallel RSA
//! engine families (`i32`, `i31`, `i62`, `i15`) sharing a common set of padding
//! helpers and a public/private key structure. This port implements the **i31**
//! family plus the shared padding code (`rsa_*_pad`/`rsa_*_unpad`,
//! `rsa_ssl_decrypt`) and the `br_rsa_*_get_default()` bindings (which select the
//! i31 implementation here, since the i62 path requires a 64x64->128 opcode and
//! the i15/i32 families are bit-identical alternates).
//!
//! The `i15`, `i32` and `i62` families are deferred: they produce identical
//! results to `i31` and only differ in internal representation / performance.
//!
//! The C "implementation classes" (`br_rsa_public`, `br_rsa_private`, ...) are
//! plain function-pointer typedefs in BearSSL; we mirror them as Rust `pub type`
//! aliases. The concrete i31 functions keep their verbatim C names
//! (`br_rsa_i31_public`, ...), and `br_rsa_*_get_default()` return them.
//!
//! ## Deviations from C
//!
//! * The C key structures use raw `unsigned char *` + length pairs. Here
//!   [`br_rsa_public_key`] / [`br_rsa_private_key`] hold `&[u8]` slices (the
//!   length is the slice length). `n_bitlen` is kept verbatim.
//! * Where C threads a PRNG as `const br_prng_class **`, this port takes
//!   `&mut dyn crate::rand::PrngState` (the runtime interface of the PRNG).
//! * Where C threads a hash function as `const br_hash_class *`, this port takes
//!   `&'static crate::hash::br_hash_class` (the descriptor), and creates running
//!   contexts via `(dig.new)()`, matching the `br_hash_class` vtable model.

use crate::hash::br_hash_class;
use crate::rand::PrngState;

/// Maximum supported RSA modulus size, in bits (`BR_MAX_RSA_SIZE`).
pub const BR_MAX_RSA_SIZE: usize = 4096;
/// Minimum supported RSA modulus size, in bits (`BR_MIN_RSA_SIZE`).
pub const BR_MIN_RSA_SIZE: usize = 512;
/// Maximum supported RSA prime factor size, in bits (`BR_MAX_RSA_FACTOR`).
pub const BR_MAX_RSA_FACTOR: usize = (BR_MAX_RSA_SIZE + 64) >> 1;

/// Encoded OID for SHA-1 (in RSA PKCS#1 signatures).
pub const BR_HASH_OID_SHA1: &[u8] = b"\x05\x2B\x0E\x03\x02\x1A";
/// Encoded OID for SHA-224 (in RSA PKCS#1 signatures).
pub const BR_HASH_OID_SHA224: &[u8] = b"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04";
/// Encoded OID for SHA-256 (in RSA PKCS#1 signatures).
pub const BR_HASH_OID_SHA256: &[u8] = b"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
/// Encoded OID for SHA-384 (in RSA PKCS#1 signatures).
pub const BR_HASH_OID_SHA384: &[u8] = b"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02";
/// Encoded OID for SHA-512 (in RSA PKCS#1 signatures).
pub const BR_HASH_OID_SHA512: &[u8] = b"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03";

/// Buffer size to hold RSA private key elements (`BR_RSA_KBUF_PRIV_SIZE`).
pub const fn BR_RSA_KBUF_PRIV_SIZE(size: usize) -> usize {
    5 * ((size + 15) >> 4)
}
/// Buffer size to hold RSA public key elements (`BR_RSA_KBUF_PUB_SIZE`).
pub const fn BR_RSA_KBUF_PUB_SIZE(size: usize) -> usize {
    4 + ((size + 7) >> 3)
}

/// RSA public key (`br_rsa_public_key`).
///
/// Both integers use unsigned big-endian representation; extra leading bytes of
/// value 0 are allowed.
#[derive(Clone, Copy)]
pub struct br_rsa_public_key<'a> {
    /// Modulus.
    pub n: &'a [u8],
    /// Public exponent.
    pub e: &'a [u8],
}

/// RSA private key (`br_rsa_private_key`).
///
/// The big integers use unsigned big-endian representation; extra leading bytes
/// of value 0 are allowed. However, `n_bitlen` MUST be exact.
#[derive(Clone, Copy)]
pub struct br_rsa_private_key<'a> {
    /// Modulus bit length (in bits, exact value).
    pub n_bitlen: u32,
    /// First prime factor.
    pub p: &'a [u8],
    /// Second prime factor.
    pub q: &'a [u8],
    /// First reduced private exponent (`d mod (p-1)`).
    pub dp: &'a [u8],
    /// Second reduced private exponent (`d mod (q-1)`).
    pub dq: &'a [u8],
    /// CRT coefficient (inverse of `q` modulo `p`).
    pub iq: &'a [u8],
}

// ---- implementation-class function-pointer typedefs -------------------------

/// Type for a RSA public key engine (`br_rsa_public`).
pub type br_rsa_public = fn(x: &mut [u8], pk: &br_rsa_public_key) -> u32;

/// Type for a RSA private key engine (`br_rsa_private`).
pub type br_rsa_private = fn(x: &mut [u8], sk: &br_rsa_private_key) -> u32;

/// Type for a RSA signature verification engine (PKCS#1 v1.5) (`br_rsa_pkcs1_vrfy`).
pub type br_rsa_pkcs1_vrfy = fn(
    x: &[u8],
    hash_oid: Option<&[u8]>,
    hash_len: usize,
    pk: &br_rsa_public_key,
    hash_out: &mut [u8],
) -> u32;

/// Type for a RSA signature generation engine (PKCS#1 v1.5) (`br_rsa_pkcs1_sign`).
pub type br_rsa_pkcs1_sign = fn(
    hash_oid: Option<&[u8]>,
    hash: &[u8],
    hash_len: usize,
    sk: &br_rsa_private_key,
    x: &mut [u8],
) -> u32;

/// Type for a RSA key-pair generator (`br_rsa_keygen`). Matches
/// [`br_rsa_i31_keygen`]'s signature (the private-key and public buffers share
/// the caller's lifetime).
pub type br_rsa_keygen = for<'a> fn(
    rng: &mut dyn PrngState,
    sk: &mut br_rsa_private_key<'a>,
    kbuf_priv: &'a mut [u8],
    out_pub: Option<&'a mut [u8]>,
    size: usize,
    pubexp: u32,
) -> (u32, Option<i31_keygen_inner::KeygenOut>);

/// Type for the modulus recomputation engine (`br_rsa_compute_modulus`).
pub type br_rsa_compute_modulus = fn(n: Option<&mut [u8]>, sk: &br_rsa_private_key) -> usize;

/// Type for the private-exponent recomputation engine (`br_rsa_compute_privexp`).
pub type br_rsa_compute_privexp =
    fn(d: Option<&mut [u8]>, sk: &br_rsa_private_key, e: u32) -> usize;

/// Type for the public-exponent recovery engine (`br_rsa_compute_pubexp`).
pub type br_rsa_compute_pubexp = fn(sk: &br_rsa_private_key) -> u32;

/// Type for a RSA signature verification engine (PSS) (`br_rsa_pss_vrfy`).
pub type br_rsa_pss_vrfy = fn(
    x: &[u8],
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    pk: &br_rsa_public_key,
) -> u32;

/// Type for a RSA signature generation engine (PSS) (`br_rsa_pss_sign`).
pub type br_rsa_pss_sign = fn(
    rng: Option<&mut dyn PrngState>,
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    sk: &br_rsa_private_key,
    x: &mut [u8],
) -> u32;

/// Type for a RSA encryption engine (OAEP) (`br_rsa_oaep_encrypt`).
pub type br_rsa_oaep_encrypt = fn(
    rnd: &mut dyn PrngState,
    dig: &'static br_hash_class,
    label: &[u8],
    pk: &br_rsa_public_key,
    dst: &mut [u8],
    src: &[u8],
) -> usize;

/// Type for a RSA decryption engine (OAEP) (`br_rsa_oaep_decrypt`).
pub type br_rsa_oaep_decrypt = fn(
    dig: &'static br_hash_class,
    label: &[u8],
    sk: &br_rsa_private_key,
    data: &mut [u8],
    len: &mut usize,
) -> u32;

// ---- shared padding ---------------------------------------------------------
mod oaep_pad;
mod oaep_unpad;
mod pkcs1_sig_pad;
mod pkcs1_sig_unpad;
mod pss_sig_pad;
mod pss_sig_unpad;
mod ssl_decrypt;

pub use oaep_pad::br_rsa_oaep_pad;
pub use oaep_unpad::br_rsa_oaep_unpad;
pub use pkcs1_sig_pad::br_rsa_pkcs1_sig_pad;
pub use pkcs1_sig_unpad::br_rsa_pkcs1_sig_unpad;
pub use pss_sig_pad::br_rsa_pss_sig_pad;
pub use pss_sig_unpad::br_rsa_pss_sig_unpad;
pub use ssl_decrypt::br_rsa_ssl_decrypt;

// ---- i31 engine -------------------------------------------------------------
mod i31_keygen;
mod i31_keygen_inner;
mod i31_modulus;
mod i31_oaep_decrypt;
mod i31_oaep_encrypt;
mod i31_pkcs1_sign;
mod i31_pkcs1_vrfy;
mod i31_priv;
mod i31_privexp;
mod i31_pss_sign;
mod i31_pss_vrfy;
mod i31_pub;
mod i31_pubexp;

pub use i31_keygen::br_rsa_i31_keygen;
pub use i31_keygen_inner::br_rsa_i31_keygen_inner;
pub use i31_modulus::br_rsa_i31_compute_modulus;
pub use i31_oaep_decrypt::br_rsa_i31_oaep_decrypt;
pub use i31_oaep_encrypt::br_rsa_i31_oaep_encrypt;
pub use i31_pkcs1_sign::br_rsa_i31_pkcs1_sign;
pub use i31_pkcs1_vrfy::br_rsa_i31_pkcs1_vrfy;
pub use i31_priv::br_rsa_i31_private;
pub use i31_privexp::br_rsa_i31_compute_privexp;
pub use i31_pss_sign::br_rsa_i31_pss_sign;
pub use i31_pss_vrfy::br_rsa_i31_pss_vrfy;
pub use i31_pub::br_rsa_i31_public;
pub use i31_pubexp::br_rsa_i31_compute_pubexp;

// ---- default bindings -------------------------------------------------------
//
// BearSSL's `rsa_default_*.c` pick i62 (if a 64x64->128 opcode exists), then
// i15 (BR_LOMUL), else i31. This portable build always selects the i31 engine.

/// see bearssl_rsa.h
pub fn br_rsa_public_get_default() -> br_rsa_public {
    br_rsa_i31_public
}
/// see bearssl_rsa.h
pub fn br_rsa_private_get_default() -> br_rsa_private {
    br_rsa_i31_private
}
/// see bearssl_rsa.h
pub fn br_rsa_pkcs1_vrfy_get_default() -> br_rsa_pkcs1_vrfy {
    br_rsa_i31_pkcs1_vrfy
}
/// see bearssl_rsa.h
pub fn br_rsa_pkcs1_sign_get_default() -> br_rsa_pkcs1_sign {
    br_rsa_i31_pkcs1_sign
}
/// see bearssl_rsa.h
pub fn br_rsa_pss_vrfy_get_default() -> br_rsa_pss_vrfy {
    br_rsa_i31_pss_vrfy
}
/// see bearssl_rsa.h
pub fn br_rsa_pss_sign_get_default() -> br_rsa_pss_sign {
    br_rsa_i31_pss_sign
}
/// see bearssl_rsa.h
pub fn br_rsa_oaep_encrypt_get_default() -> br_rsa_oaep_encrypt {
    br_rsa_i31_oaep_encrypt
}
/// see bearssl_rsa.h
pub fn br_rsa_oaep_decrypt_get_default() -> br_rsa_oaep_decrypt {
    br_rsa_i31_oaep_decrypt
}
/// see bearssl_rsa.h (`br_rsa_keygen_get_default`)
pub fn br_rsa_keygen_get_default() -> br_rsa_keygen {
    br_rsa_i31_keygen
}
/// see bearssl_rsa.h (`br_rsa_compute_modulus_get_default`)
pub fn br_rsa_compute_modulus_get_default() -> br_rsa_compute_modulus {
    br_rsa_i31_compute_modulus
}
/// see bearssl_rsa.h (`br_rsa_compute_privexp_get_default`)
pub fn br_rsa_compute_privexp_get_default() -> br_rsa_compute_privexp {
    br_rsa_i31_compute_privexp
}
/// see bearssl_rsa.h (`br_rsa_compute_pubexp_get_default`)
pub fn br_rsa_compute_pubexp_get_default() -> br_rsa_compute_pubexp {
    br_rsa_i31_compute_pubexp
}
