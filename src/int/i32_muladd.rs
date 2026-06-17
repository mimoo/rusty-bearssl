/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_muladd_small` (mirrors `src/int/i32_muladd.c`).

use super::br_i32_word;
use super::i32_add::br_i32_add;
use super::i32_div32::{br_div, br_rem};
use super::i32_sub::br_i32_sub;
use crate::inner::{EQ, GT, LT, MUL, MUX};

/// Multiply x[] by 2^32 and then add integer z, modulo m[]. x[] and m[] must be
/// distinct arrays with the same announced bit length, which must match the
/// true bit length of m.
pub fn br_i32_muladd_small(x: &mut [u32], z: u32, m: &[u32]) {
    let m_bitlen = m[0];
    if m_bitlen == 0 {
        return;
    }
    if m_bitlen <= 32 {
        x[1] = br_rem(x[1], z, m[1]);
        return;
    }
    let mlen = ((m_bitlen + 31) >> 5) as usize;

    let a0 = br_i32_word(x, m_bitlen - 32);
    let hi = x[mlen];
    x.copy_within(1..1 + (mlen - 1), 2);
    x[1] = z;
    let a1 = br_i32_word(x, m_bitlen - 32);
    let b0 = br_i32_word(m, m_bitlen - 32);

    let g = br_div(a0, a1, b0);
    let q = MUX(EQ(a0, b0), 0xFFFFFFFF, MUX(EQ(g, 0), 0, g.wrapping_sub(1)));

    let mut cc: u64 = 0;
    let mut tb: u32 = 1;
    for u in 1..=mlen {
        let mw = m[u];
        let zl = MUL(mw, q).wrapping_add(cc);
        cc = (zl >> 32) as u64;
        let zw = zl as u32;
        let xw = x[u];
        let nxw = xw.wrapping_sub(zw);
        cc = cc.wrapping_add(GT(nxw, xw) as u64);
        x[u] = nxw;
        tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
    }

    let chf = (cc >> 32) as u32;
    let clow = cc as u32;
    let over = chf | GT(clow, hi);
    let under = !over & (tb | (!chf & LT(clow, hi)));
    br_i32_add(x, m, over);
    br_i32_sub(x, m, under);
}
