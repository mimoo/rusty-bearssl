/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_encode` (mirrors `src/int/i31_encode.c`).

use crate::inner::br_enc32be;

/// Encode an integer into its big-endian unsigned representation. If `len` is
/// too short the integer is truncated; if too long, extra bytes are zero.
pub fn br_i31_encode(dst: &mut [u8], mut len: usize, x: &[u32]) {
    let xlen = ((x[0] + 31) >> 5) as usize;
    if xlen == 0 {
        for b in dst[..len].iter_mut() {
            *b = 0;
        }
        return;
    }
    // `buf` is a write cursor measured from the end of dst (mirrors the C
    // pointer that starts at dst+len and walks backwards).
    let mut buf = len;
    let mut k = 1usize;
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while len != 0 {
        let w = if k <= xlen { x[k] } else { 0 };
        k += 1;
        if acc_len == 0 {
            acc = w;
            acc_len = 31;
        } else {
            let z = acc | (w << acc_len);
            acc_len -= 1;
            acc = w >> (31 - acc_len);
            if len >= 4 {
                buf -= 4;
                len -= 4;
                br_enc32be(&mut dst[buf..], z);
            } else {
                match len {
                    3 => {
                        dst[buf - 3] = (z >> 16) as u8;
                        dst[buf - 2] = (z >> 8) as u8;
                        dst[buf - 1] = z as u8;
                    }
                    2 => {
                        dst[buf - 2] = (z >> 8) as u8;
                        dst[buf - 1] = z as u8;
                    }
                    1 => {
                        dst[buf - 1] = z as u8;
                    }
                    _ => {}
                }
                return;
            }
        }
    }
}
