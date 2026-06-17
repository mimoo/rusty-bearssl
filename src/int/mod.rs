/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Big-integer arithmetic (`src/int/`).
//!
//! Mirrors BearSSL's `src/int/` directory. Four parallel families implement the
//! same operations over different internal representations:
//!
//! * `i32`: 32-bit value words.
//! * `i31`: 31-bit value words packed in 32-bit slots (top bit clear).
//! * `i15`: 15-bit value words packed in 16-bit slots (`u16`).
//! * `i62`: a 64x64->128 Montgomery exponentiation reusing the i31 codecs.
//!
//! For the i32/i31 families an integer `x[]` is an array of `u32` where `x[0]`
//! is the (possibly encoded) announced bit length and `x[1..]` holds the value
//! in little-endian order. For i15 the same layout is used over `u16`.
//!
//! The inline helpers from `inner.h` (`br_i31_zero`, `br_i32_word`, ...) live
//! here as module functions; `br_divrem`/`br_rem`/`br_div` live in
//! [`i32_div32`].

use crate::inner::MUX;

// ---- i32 family -------------------------------------------------------------
mod i32_add;
mod i32_bitlen;
mod i32_decmod;
mod i32_decode;
mod i32_decred;
mod i32_div32;
mod i32_encode;
mod i32_fmont;
mod i32_iszero;
mod i32_modpow;
mod i32_montmul;
mod i32_mulacc;
mod i32_muladd;
mod i32_ninv32;
mod i32_reduce;
mod i32_sub;
mod i32_tmont;

// ---- i31 family -------------------------------------------------------------
mod i31_add;
mod i31_bitlen;
mod i31_decmod;
mod i31_decode;
mod i31_decred;
mod i31_encode;
mod i31_fmont;
mod i31_iszero;
mod i31_moddiv;
mod i31_modpow;
mod i31_modpow2;
mod i31_montmul;
mod i31_mulacc;
mod i31_muladd;
mod i31_ninv31;
mod i31_reduce;
mod i31_rshift;
mod i31_sub;
mod i31_tmont;

// ---- i15 family -------------------------------------------------------------
mod i15_add;
mod i15_bitlen;
mod i15_decmod;
mod i15_decode;
mod i15_decred;
mod i15_encode;
mod i15_fmont;
mod i15_iszero;
mod i15_moddiv;
mod i15_modpow;
mod i15_modpow2;
mod i15_montmul;
mod i15_mulacc;
mod i15_muladd;
mod i15_ninv15;
mod i15_reduce;
mod i15_rshift;
mod i15_sub;
mod i15_tmont;

// ---- i62 family -------------------------------------------------------------
mod i62_modpow2;

// ---- public re-exports ------------------------------------------------------

pub use i32_add::br_i32_add;
pub use i32_bitlen::br_i32_bit_length;
pub use i32_decmod::br_i32_decode_mod;
pub use i32_decode::br_i32_decode;
pub use i32_decred::br_i32_decode_reduce;
pub use i32_div32::{br_div, br_divrem, br_rem};
pub use i32_encode::br_i32_encode;
pub use i32_fmont::br_i32_from_monty;
pub use i32_iszero::br_i32_iszero;
pub use i32_modpow::br_i32_modpow;
pub use i32_montmul::br_i32_montymul;
pub use i32_mulacc::br_i32_mulacc;
pub use i32_muladd::br_i32_muladd_small;
pub use i32_ninv32::br_i32_ninv32;
pub use i32_reduce::br_i32_reduce;
pub use i32_sub::br_i32_sub;
pub use i32_tmont::br_i32_to_monty;

pub use i31_add::br_i31_add;
pub use i31_bitlen::br_i31_bit_length;
pub use i31_decmod::br_i31_decode_mod;
pub use i31_decode::br_i31_decode;
pub use i31_decred::br_i31_decode_reduce;
pub use i31_encode::br_i31_encode;
pub use i31_fmont::br_i31_from_monty;
pub use i31_iszero::br_i31_iszero;
pub use i31_moddiv::br_i31_moddiv;
pub use i31_modpow::br_i31_modpow;
pub use i31_modpow2::br_i31_modpow_opt;
pub use i31_montmul::br_i31_montymul;
pub use i31_mulacc::br_i31_mulacc;
pub use i31_muladd::br_i31_muladd_small;
pub use i31_ninv31::br_i31_ninv31;
pub use i31_reduce::br_i31_reduce;
pub use i31_rshift::br_i31_rshift;
pub use i31_sub::br_i31_sub;
pub use i31_tmont::br_i31_to_monty;

pub use i15_add::br_i15_add;
pub use i15_bitlen::br_i15_bit_length;
pub use i15_decmod::br_i15_decode_mod;
pub use i15_decode::br_i15_decode;
pub use i15_decred::br_i15_decode_reduce;
pub use i15_encode::br_i15_encode;
pub use i15_fmont::br_i15_from_monty;
pub use i15_iszero::br_i15_iszero;
pub use i15_moddiv::br_i15_moddiv;
pub use i15_modpow::br_i15_modpow;
pub use i15_modpow2::br_i15_modpow_opt;
pub use i15_montmul::br_i15_montymul;
pub use i15_mulacc::br_i15_mulacc;
pub use i15_muladd::br_i15_muladd_small;
pub use i15_ninv15::br_i15_ninv15;
pub use i15_reduce::br_i15_reduce;
pub use i15_rshift::br_i15_rshift;
pub use i15_sub::br_i15_sub;
pub use i15_tmont::br_i15_to_monty;

pub use i62_modpow2::{br_i62_modpow_opt, br_i62_modpow_opt_as_i31};

// ---- shared inline helpers (from inner.h) -----------------------------------

/// Zeroize an i31 integer: set the (encoded) announced bit length and clear the
/// corresponding words. Mirrors the `br_i31_zero` inline.
pub fn br_i31_zero(x: &mut [u32], bit_len: u32) {
    x[0] = bit_len;
    let n = ((bit_len + 31) >> 5) as usize;
    for w in x[1..1 + n].iter_mut() {
        *w = 0;
    }
}

/// Zeroize an i32 integer. Mirrors the `br_i32_zero` inline.
pub fn br_i32_zero(x: &mut [u32], bit_len: u32) {
    x[0] = bit_len;
    let n = ((bit_len + 31) >> 5) as usize;
    for w in x[1..1 + n].iter_mut() {
        *w = 0;
    }
}

/// Zeroize an i15 integer. Mirrors the `br_i15_zero` inline.
pub fn br_i15_zero(x: &mut [u16], bit_len: u16) {
    x[0] = bit_len;
    let n = ((bit_len as u32 + 15) >> 4) as usize;
    for w in x[1..1 + n].iter_mut() {
        *w = 0;
    }
}

/// Extract one 32-bit word from an i32 integer at a given bit offset. Mirrors
/// the `br_i32_word` inline.
pub fn br_i32_word(a: &[u32], off: u32) -> u32 {
    let u = (off >> 5) as usize + 1;
    let j = off & 31;
    if j == 0 {
        a[u]
    } else {
        (a[u] >> j) | (a[u + 1] << (32 - j))
    }
}

/// Number of `u32` slots (header + value words) occupied by an i31/i32 value of
/// the given announced bit length; matches the C `mlen = ((m[0]+63)>>5)`.
#[inline(always)]
pub(crate) fn i31_words(bit_len: u32) -> usize {
    ((bit_len + 63) >> 5) as usize
}

/// Same as [`i31_words`] for the i32 family (identical formula).
#[inline(always)]
pub(crate) fn i32_words(bit_len: u32) -> usize {
    ((bit_len + 63) >> 5) as usize
}

/// Number of `u16` slots (header + value words) occupied by an i15 value of the
/// given announced bit length; matches the C `mlen = ((m[0]+31)>>4)`.
#[inline(always)]
pub(crate) fn i15_words(bit_len: u16) -> usize {
    ((bit_len as u32 + 31) >> 4) as usize
}

/// Word-wise constant-time conditional copy of `n` `u32` words. Mirrors
/// `br_ccopy` over a word-aligned region: the byte-wise `MUX` of the C code is
/// equivalent to a per-word `MUX` when `ctl` is constant across the copy.
#[inline(always)]
pub(crate) fn ccopy_words(ctl: u32, dst: &mut [u32], src: &[u32], n: usize) {
    for k in 0..n {
        dst[k] = MUX(ctl, src[k], dst[k]);
    }
}

/// Word-wise constant-time conditional copy of `n` `u16` words.
#[inline(always)]
pub(crate) fn ccopy_words16(ctl: u32, dst: &mut [u16], src: &[u16], n: usize) {
    for k in 0..n {
        dst[k] = MUX(ctl, src[k] as u32, dst[k] as u32) as u16;
    }
}
