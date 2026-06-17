/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Shared inline helpers and constant-time primitives.
//!
//! This mirrors the inline functions and macros declared in BearSSL's
//! `src/inner.h`: integer (de)serialization helpers and the constant-time
//! arithmetic/comparison primitives used throughout the library.

#![allow(non_snake_case)]

// ==================================================================== //
// Encoding / decoding of 16/32/64-bit integers, big- and little-endian.
//
// The C versions take `void *` and read/write exactly N bytes; here we take
// byte slices and operate on the first N bytes (panicking, as in any Rust
// out-of-bounds access, if the slice is too short — callers always pass an
// adequately sized buffer, matching the C contract).

#[inline(always)]
pub fn br_enc16le(dst: &mut [u8], x: u32) {
    dst[..2].copy_from_slice(&(x as u16).to_le_bytes());
}

#[inline(always)]
pub fn br_enc16be(dst: &mut [u8], x: u32) {
    dst[..2].copy_from_slice(&(x as u16).to_be_bytes());
}

#[inline(always)]
pub fn br_dec16le(src: &[u8]) -> u32 {
    u16::from_le_bytes([src[0], src[1]]) as u32
}

#[inline(always)]
pub fn br_dec16be(src: &[u8]) -> u32 {
    u16::from_be_bytes([src[0], src[1]]) as u32
}

#[inline(always)]
pub fn br_enc32le(dst: &mut [u8], x: u32) {
    dst[..4].copy_from_slice(&x.to_le_bytes());
}

#[inline(always)]
pub fn br_enc32be(dst: &mut [u8], x: u32) {
    dst[..4].copy_from_slice(&x.to_be_bytes());
}

#[inline(always)]
pub fn br_dec32le(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

#[inline(always)]
pub fn br_dec32be(src: &[u8]) -> u32 {
    u32::from_be_bytes([src[0], src[1], src[2], src[3]])
}

#[inline(always)]
pub fn br_enc64le(dst: &mut [u8], x: u64) {
    dst[..8].copy_from_slice(&x.to_le_bytes());
}

#[inline(always)]
pub fn br_enc64be(dst: &mut [u8], x: u64) {
    dst[..8].copy_from_slice(&x.to_be_bytes());
}

#[inline(always)]
pub fn br_dec64le(src: &[u8]) -> u64 {
    u64::from_le_bytes(src[..8].try_into().unwrap())
}

#[inline(always)]
pub fn br_dec64be(src: &[u8]) -> u64 {
    u64::from_be_bytes(src[..8].try_into().unwrap())
}

/// Byte-swap a 32-bit integer.
#[inline(always)]
pub fn br_swap32(x: u32) -> u32 {
    x.swap_bytes()
}

// ==================================================================== //
// Constant-time primitives.
//
// These manipulate 32-bit values to provide constant-time comparisons and
// multiplexers. Boolean "ctl" values MUST be 0 or 1. Ported bit-for-bit from
// inner.h; do not simplify with branches.

/// Negate a boolean.
#[inline(always)]
pub fn NOT(ctl: u32) -> u32 {
    ctl ^ 1
}

/// Multiplexer: returns x if ctl == 1, y if ctl == 0.
#[inline(always)]
pub fn MUX(ctl: u32, x: u32, y: u32) -> u32 {
    y ^ (ctl.wrapping_neg() & (x ^ y))
}

/// Equality check: returns 1 if x == y, 0 otherwise.
#[inline(always)]
pub fn EQ(x: u32, y: u32) -> u32 {
    let q = x ^ y;
    NOT((q | q.wrapping_neg()) >> 31)
}

/// Inequality check: returns 1 if x != y, 0 otherwise.
#[inline(always)]
pub fn NEQ(x: u32, y: u32) -> u32 {
    let q = x ^ y;
    (q | q.wrapping_neg()) >> 31
}

/// Comparison: returns 1 if x > y, 0 otherwise.
#[inline(always)]
pub fn GT(x: u32, y: u32) -> u32 {
    let z = y.wrapping_sub(x);
    (z ^ ((x ^ y) & (x ^ z))) >> 31
}

/// Greater-or-equal: 1 if x >= y, 0 otherwise.
#[inline(always)]
pub fn GE(x: u32, y: u32) -> u32 {
    NOT(GT(y, x))
}

/// Lower-than: 1 if x < y, 0 otherwise.
#[inline(always)]
pub fn LT(x: u32, y: u32) -> u32 {
    GT(y, x)
}

/// Lower-or-equal: 1 if x <= y, 0 otherwise.
#[inline(always)]
pub fn LE(x: u32, y: u32) -> u32 {
    NOT(GT(x, y))
}

/// General comparison: returns -1, 0 or 1 depending on whether x is lower
/// than, equal to, or greater than y.
#[inline(always)]
pub fn CMP(x: u32, y: u32) -> i32 {
    (GT(x, y) as i32) | -(GT(y, x) as i32)
}

/// Returns 1 if x == 0, 0 otherwise. The operand is signed.
#[inline(always)]
pub fn EQ0(x: i32) -> u32 {
    let q = x as u32;
    !(q | q.wrapping_neg()) >> 31
}

/// Returns 1 if x > 0, 0 otherwise. The operand is signed.
#[inline(always)]
pub fn GT0(x: i32) -> u32 {
    let q = x as u32;
    (!q & q.wrapping_neg()) >> 31
}

/// Returns 1 if x >= 0, 0 otherwise. The operand is signed.
#[inline(always)]
pub fn GE0(x: i32) -> u32 {
    !(x as u32) >> 31
}

/// Returns 1 if x < 0, 0 otherwise. The operand is signed.
#[inline(always)]
pub fn LT0(x: i32) -> u32 {
    (x as u32) >> 31
}

/// Returns 1 if x <= 0, 0 otherwise. The operand is signed.
#[inline(always)]
pub fn LE0(x: i32) -> u32 {
    let q = x as u32;
    (q | !q.wrapping_neg()) >> 31
}

/// Compute the bit length of a 32-bit integer (0..=32).
#[inline(always)]
pub fn BIT_LENGTH(mut x: u32) -> u32 {
    let mut k = NEQ(x, 0);
    let mut c;
    c = GT(x, 0xFFFF);
    x = MUX(c, x >> 16, x);
    k += c << 4;
    c = GT(x, 0x00FF);
    x = MUX(c, x >> 8, x);
    k += c << 3;
    c = GT(x, 0x000F);
    x = MUX(c, x >> 4, x);
    k += c << 2;
    c = GT(x, 0x0003);
    x = MUX(c, x >> 2, x);
    k += c << 1;
    k += GT(x, 0x0001);
    k
}

/// Compute the minimum of x and y.
#[inline(always)]
pub fn MIN(x: u32, y: u32) -> u32 {
    MUX(GT(x, y), y, x)
}

/// Compute the maximum of x and y.
#[inline(always)]
pub fn MAX(x: u32, y: u32) -> u32 {
    MUX(GT(x, y), x, y)
}

/// Multiply two 32-bit integers, with a 64-bit result.
#[inline(always)]
pub fn MUL(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}

/// Multiply two 31-bit integers, with a 62-bit result.
#[inline(always)]
pub fn MUL31(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}

/// Low 31 bits of the product of two 31-bit integers.
#[inline(always)]
pub fn MUL31_lo(x: u32, y: u32) -> u32 {
    x.wrapping_mul(y) & 0x7FFFFFFF
}

/// Multiply two words whose lengths sum to at most 31 bits.
#[inline(always)]
pub fn MUL15(x: u32, y: u32) -> u32 {
    x.wrapping_mul(y)
}

/// Arithmetic right shift (sign bit is copied).
#[inline(always)]
pub fn ARSH(x: u32, n: u32) -> u32 {
    ((x as i32) >> n) as u32
}
