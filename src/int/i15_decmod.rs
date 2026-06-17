/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_decode_mod` (mirrors `src/int/i15_decmod.c`).

use crate::inner::{CMP, EQ, MUX};

/// Decode an integer requiring it to be lower than m[]. Returns 1 if it fits.
pub fn br_i15_decode_mod(x: &mut [u16], src: &[u8], len: usize, m: &[u16]) -> u32 {
    let buf = src;
    let mlen = ((m[0] + 15) >> 4) as usize;
    let mut tlen = mlen << 1;
    if tlen < len {
        tlen = len;
    }
    tlen += 4;
    let mut r: u32 = 0;
    for pass in 0..2 {
        let mut v = 1usize;
        let mut acc: u32 = 0;
        let mut acc_len: i32 = 0;
        for u in 0..tlen {
            let b = if u < len { buf[len - 1 - u] as u32 } else { 0 };
            acc |= b << acc_len;
            acc_len += 8;
            if acc_len >= 15 {
                let xw = acc & 0x7FFF;
                acc_len -= 15;
                acc = b >> (8 - acc_len);
                if v <= mlen {
                    if pass != 0 {
                        x[v] = (r & xw) as u16;
                    } else {
                        let cc = CMP(xw, m[v] as u32) as u32;
                        r = MUX(EQ(cc, 0), r, cc);
                    }
                } else if pass == 0 {
                    r = MUX(EQ(xw, 0), r, 1);
                }
                v += 1;
            }
        }
        r >>= 1;
        r |= r << 1;
    }
    x[0] = m[0];
    r & 1
}
