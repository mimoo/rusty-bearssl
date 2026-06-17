/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_decode` (mirrors `src/int/i15_decode.c`).

use super::i15_bitlen::br_i15_bit_length;

/// Decode an integer from its big-endian unsigned representation.
pub fn br_i15_decode(x: &mut [u16], src: &[u8], mut len: usize) {
    let buf = src;
    let mut v = 1usize;
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while len > 0 {
        len -= 1;
        let b = buf[len] as u32;
        acc |= b << acc_len;
        acc_len += 8;
        if acc_len >= 15 {
            x[v] = (acc & 0x7FFF) as u16;
            v += 1;
            acc_len -= 15;
            acc >>= 15;
        }
    }
    if acc_len != 0 {
        x[v] = acc as u16;
        v += 1;
    }
    x[0] = br_i15_bit_length(&x[1..], v - 1) as u16;
}
