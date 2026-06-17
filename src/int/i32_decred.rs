/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_decode_reduce` (mirrors `src/int/i32_decred.c`).

use super::br_i32_zero;
use super::i32_decode::br_i32_decode;
use super::i32_muladd::br_i32_muladd_small;
use crate::inner::br_dec32be;

/// Decode an integer and reduce it modulo m[]. The announced bit length of the
/// result is that of the modulus.
pub fn br_i32_decode_reduce(x: &mut [u32], src: &[u8], len: usize, m: &[u32]) {
    let m_bitlen = m[0];

    if m_bitlen == 0 {
        x[0] = 0;
        return;
    }

    br_i32_zero(x, m_bitlen);

    let mblen = ((m_bitlen + 7) >> 3) as usize;
    let mut k = mblen - 1;

    if k >= len {
        br_i32_decode(x, src, len);
        x[0] = m_bitlen;
        return;
    }

    let buf = src;
    let mut q = (len - k + 3) & !3usize;

    if q > len {
        let mut w: u32 = 0;
        for _i in 0..4 {
            w <<= 8;
            if q <= len {
                w |= buf[len - q] as u32;
            }
            q -= 1;
        }
        br_i32_muladd_small(x, w, m);
    } else {
        br_i32_decode(x, buf, len - q);
        x[0] = m_bitlen;
    }

    k = len - q;
    while k < len {
        br_i32_muladd_small(x, br_dec32be(&buf[k..]), m);
        k += 4;
    }
}
