/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_decode_mod` (mirrors `src/int/i32_decmod.c`).

use super::br_i32_zero;
use crate::inner::{CMP, EQ, MUX};

/// Decode an integer requiring it to be lower than m[]. Returns 1 if the value
/// fits, 0 otherwise (then x is set to 0). x's announced bit length is m's.
pub fn br_i32_decode_mod(x: &mut [u32], src: &[u8], len: usize, m: &[u32]) -> u32 {
    let buf = src;

    let mlen = ((m[0] + 7) >> 3) as usize;
    let mut r: u32 = 0;
    let mut u = if mlen > len { mlen } else { len };
    while u > 0 {
        let v = u - 1;
        let mb = if v >= mlen {
            0
        } else {
            (m[1 + (v >> 2)] >> ((v & 3) << 3)) & 0xFF
        };
        let xb = if v >= len { 0 } else { buf[len - u] as u32 };
        r = MUX(EQ(r, 0), CMP(xb, mb) as u32, r);
        u -= 1;
    }

    r >>= 24;
    br_i32_zero(x, m[0]);
    u = if mlen > len { len } else { mlen };
    while u > 0 {
        let xb = (buf[len - u] as u32) & r;
        u -= 1;
        x[1 + (u >> 2)] |= xb << ((u & 3) << 3);
    }
    r >> 7
}
