/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_muladd_small` (mirrors `src/int/i31_muladd.c`).

use super::i31_add::br_i31_add;
use super::i31_sub::br_i31_sub;
use super::i32_div32::{br_div, br_rem};
use crate::inner::{EQ, GT, LT, MUL31, MUX};

/// Multiply x[] by 2^31 and then add integer z, modulo m[]. x[] and m[] must
/// be distinct arrays with the same announced bit length, which must match the
/// true bit length of m. z must fit in 31 bits.
pub fn br_i31_muladd_small(x: &mut [u32], z: u32, m: &[u32]) {
    let m_bitlen = m[0];
    if m_bitlen == 0 {
        return;
    }
    if m_bitlen <= 31 {
        let hi = x[1] >> 1;
        let lo = (x[1] << 31) | z;
        x[1] = br_rem(hi, lo, m[1]);
        return;
    }
    let mlen = ((m_bitlen + 31) >> 5) as usize;
    let mblr = m_bitlen & 31;

    let hi = x[mlen];
    let a0;
    let a1;
    let b0;
    if mblr == 0 {
        a0 = x[mlen];
        x.copy_within(1..1 + (mlen - 1), 2);
        x[1] = z;
        a1 = x[mlen];
        b0 = m[mlen];
    } else {
        a0 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr)) & 0x7FFFFFFF;
        x.copy_within(1..1 + (mlen - 1), 2);
        x[1] = z;
        a1 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr)) & 0x7FFFFFFF;
        b0 = ((m[mlen] << (31 - mblr)) | (m[mlen - 1] >> mblr)) & 0x7FFFFFFF;
    }

    let g = br_div(a0 >> 1, a1 | (a0 << 31), b0);
    let q = MUX(
        EQ(a0, b0),
        0x7FFFFFFF,
        MUX(EQ(g, 0), 0, g.wrapping_sub(1)),
    );

    let mut cc: u32 = 0;
    let mut tb: u32 = 1;
    for u in 1..=mlen {
        let mw = m[u];
        let zl = MUL31(mw, q).wrapping_add(cc as u64);
        cc = (zl >> 31) as u32;
        let zw = (zl as u32) & 0x7FFFFFFF;
        let xw = x[u];
        let mut nxw = xw.wrapping_sub(zw);
        cc = cc.wrapping_add(nxw >> 31);
        nxw &= 0x7FFFFFFF;
        x[u] = nxw;
        tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
    }

    let over = GT(cc, hi);
    let under = !over & (tb | LT(cc, hi));
    br_i31_add(x, m, over);
    br_i31_sub(x, m, under);
}
