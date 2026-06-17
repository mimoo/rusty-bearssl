/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_decode` (mirrors `src/int/i31_decode.c`).

use super::i31_bitlen::br_i31_bit_length;

/// Decode an integer from its big-endian unsigned representation. The "true"
/// bit length is computed and set in x[0]; all words corresponding to the full
/// `len` bytes of the source are set.
pub fn br_i31_decode(x: &mut [u32], src: &[u8], len: usize) {
    let buf = src;
    let mut u = len;
    let mut v = 1usize;
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while u > 0 {
        u -= 1;
        let b = buf[u] as u32;
        acc |= b << acc_len;
        acc_len += 8;
        if acc_len >= 31 {
            x[v] = acc & 0x7FFFFFFF;
            v += 1;
            acc_len -= 31;
            acc = b >> (8 - acc_len);
        }
    }
    if acc_len != 0 {
        x[v] = acc;
        v += 1;
    }
    x[0] = br_i31_bit_length(&x[1..], v - 1);
}
