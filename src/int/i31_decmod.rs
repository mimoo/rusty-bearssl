/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_decode_mod` (mirrors `src/int/i31_decmod.c`).

use crate::inner::{CMP, EQ, MUX};

/// Decode an integer from its big-endian representation, requiring it to be
/// lower than m[]. Returns 1 if the value fits, 0 otherwise (and then x is set
/// to 0). The announced bit length of x is set to that of m.
pub fn br_i31_decode_mod(x: &mut [u32], src: &[u8], len: usize, m: &[u32]) -> u32 {
    let buf = src;
    let mlen = ((m[0] + 31) >> 5) as usize;
    let mut tlen = mlen << 2;
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
            if acc_len >= 31 {
                let xw = acc & 0x7FFFFFFF;
                acc_len -= 31;
                acc = b >> (8 - acc_len);
                if v <= mlen {
                    if pass != 0 {
                        x[v] = r & xw;
                    } else {
                        let cc = CMP(xw, m[v]) as u32;
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
