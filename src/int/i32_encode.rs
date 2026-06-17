/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_encode` (mirrors `src/int/i32_encode.c`).

use crate::inner::br_enc32be;

/// Encode an integer into its big-endian unsigned representation.
pub fn br_i32_encode(dst: &mut [u8], mut len: usize, x: &[u32]) {
    let mut pos = 0usize; // write cursor into dst (mirrors C 'buf')

    let mut k = ((x[0] + 7) >> 3) as usize;
    while len > k {
        dst[pos] = 0;
        pos += 1;
        len -= 1;
    }

    k = (len + 3) >> 2;
    match len & 3 {
        3 => {
            dst[pos] = (x[k] >> 16) as u8;
            pos += 1;
            dst[pos] = (x[k] >> 8) as u8;
            pos += 1;
            dst[pos] = x[k] as u8;
            pos += 1;
            k -= 1;
        }
        2 => {
            dst[pos] = (x[k] >> 8) as u8;
            pos += 1;
            dst[pos] = x[k] as u8;
            pos += 1;
            k -= 1;
        }
        1 => {
            dst[pos] = x[k] as u8;
            pos += 1;
            k -= 1;
        }
        _ => {}
    }

    while k > 0 {
        br_enc32be(&mut dst[pos..], x[k]);
        k -= 1;
        pos += 4;
    }
}
