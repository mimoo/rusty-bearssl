/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_decode_reduce` (mirrors `src/int/i15_decred.c`).

use super::br_i15_zero;
use super::i15_decode::br_i15_decode;
use super::i15_muladd::br_i15_muladd_small;
use super::i15_rshift::br_i15_rshift;

/// Decode an integer and reduce it modulo m[]. The announced bit length of the
/// result is that of the modulus.
pub fn br_i15_decode_reduce(x: &mut [u16], src: &[u8], len: usize, m: &[u16]) {
    let m_ebitlen = m[0] as u32;

    if m_ebitlen == 0 {
        x[0] = 0;
        return;
    }

    br_i15_zero(x, m[0]);

    let mut m_rbitlen = m_ebitlen >> 4;
    m_rbitlen = (m_ebitlen & 15) + (m_rbitlen << 4) - m_rbitlen;
    let mblen = ((m_rbitlen + 7) >> 3) as usize;
    let mut k = mblen - 1;
    if k >= len {
        br_i15_decode(x, src, len);
        x[0] = m[0];
        return;
    }
    let buf = src;
    br_i15_decode(x, buf, k);
    x[0] = m[0];

    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while k < len {
        let v = buf[k] as u32;
        k += 1;
        acc = (acc << 8) | v;
        acc_len += 8;
        if acc_len >= 15 {
            br_i15_muladd_small(x, (acc >> (acc_len - 15)) as u16, m);
            acc_len -= 15;
            acc &= !(u32::MAX << acc_len);
        }
    }

    if acc_len != 0 {
        acc = (acc | ((x[1] as u32) << acc_len)) & 0x7FFF;
        br_i15_rshift(x, 15 - acc_len as i32);
        br_i15_muladd_small(x, acc as u16, m);
    }
}
