/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_decode_reduce` (mirrors `src/int/i31_decred.c`).

use super::br_i31_zero;
use super::i31_decode::br_i31_decode;
use super::i31_muladd::br_i31_muladd_small;
use super::i31_rshift::br_i31_rshift;

/// Decode an integer from its big-endian representation and reduce it modulo
/// m[]. The announced bit length of the result is that of the modulus.
pub fn br_i31_decode_reduce(x: &mut [u32], src: &[u8], len: usize, m: &[u32]) {
    let m_ebitlen = m[0];

    if m_ebitlen == 0 {
        x[0] = 0;
        return;
    }

    br_i31_zero(x, m_ebitlen);

    let mut m_rbitlen = m_ebitlen >> 5;
    m_rbitlen = (m_ebitlen & 31) + (m_rbitlen << 5) - m_rbitlen;
    let mblen = ((m_rbitlen + 7) >> 3) as usize;
    let mut k = mblen - 1;
    if k >= len {
        br_i31_decode(x, src, len);
        x[0] = m_ebitlen;
        return;
    }
    let buf = src;
    br_i31_decode(x, buf, k);
    x[0] = m_ebitlen;

    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while k < len {
        let v = buf[k] as u32;
        k += 1;
        if acc_len >= 23 {
            acc_len -= 23;
            acc <<= 8 - acc_len;
            acc |= v >> acc_len;
            br_i31_muladd_small(x, acc, m);
            acc = v & (0xFF >> (8 - acc_len));
        } else {
            acc = (acc << 8) | v;
            acc_len += 8;
        }
    }

    if acc_len != 0 {
        acc = (acc | (x[1] << acc_len)) & 0x7FFFFFFF;
        br_i31_rshift(x, 31 - acc_len);
        br_i31_muladd_small(x, acc, m);
    }
}
