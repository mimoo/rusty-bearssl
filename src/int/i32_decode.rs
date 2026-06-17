/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_decode` (mirrors `src/int/i32_decode.c`).

use super::i32_bitlen::br_i32_bit_length;
use crate::inner::{br_dec16be, br_dec32be};

/// Decode an integer from its big-endian unsigned representation.
pub fn br_i32_decode(x: &mut [u32], src: &[u8], len: usize) {
    let buf = src;
    let mut u = len;
    let mut v = 1usize;
    loop {
        if u < 4 {
            let w;
            if u < 2 {
                if u == 0 {
                    break;
                } else {
                    w = buf[0] as u32;
                }
            } else if u == 2 {
                w = br_dec16be(buf);
            } else {
                w = ((buf[0] as u32) << 16) | br_dec16be(&buf[1..]);
            }
            x[v] = w;
            v += 1;
            break;
        } else {
            u -= 4;
            x[v] = br_dec32be(&buf[u..]);
            v += 1;
        }
    }
    x[0] = br_i32_bit_length(&x[1..], v - 1);
}
