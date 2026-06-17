/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_muladd_small` (mirrors `src/int/i15_muladd.c`).

use super::i15_add::br_i15_add;
use super::i15_sub::br_i15_sub;
use crate::inner::{EQ, GT, LE, LT, MUL15, MUX};

/// Constant-time division. The divisor must not be larger than 16 bits, and the
/// quotient must fit on 17 bits. The remainder is returned via `r` if Some.
fn divrem16(mut x: u32, d: u32, r: Option<&mut u32>) -> u32 {
    let mut q: u32 = 0;
    let mut d = d << 16;
    let mut i = 16i32;
    while i >= 0 {
        let ctl = LE(d, x);
        q |= ctl << i;
        x = x.wrapping_sub(ctl.wrapping_neg() & d);
        d >>= 1;
        i -= 1;
    }
    if let Some(r) = r {
        *r = x;
    }
    q
}

/// Multiply x[] by 2^15 and then add integer z, modulo m[].
pub fn br_i15_muladd_small(x: &mut [u16], z: u16, m: &[u16]) {
    let m_bitlen = m[0] as u32;
    if m_bitlen == 0 {
        return;
    }
    if m_bitlen <= 15 {
        let mut rem = 0u32;
        divrem16(((x[1] as u32) << 15) | z as u32, m[1] as u32, Some(&mut rem));
        x[1] = rem as u16;
        return;
    }
    let mlen = ((m_bitlen + 15) >> 4) as usize;
    let mblr = m_bitlen & 15;

    let hi = x[mlen] as u32;
    let a0;
    let a;
    let b;
    if mblr == 0 {
        a0 = x[mlen] as u32;
        x.copy_within(1..1 + (mlen - 1), 2);
        x[1] = z;
        a = (a0 << 15) + x[mlen] as u32;
        b = m[mlen] as u32;
    } else {
        a0 = ((x[mlen] as u32) << (15 - mblr)) | ((x[mlen - 1] as u32) >> mblr);
        x.copy_within(1..1 + (mlen - 1), 2);
        x[1] = z;
        a = (a0 << 15)
            | ((((x[mlen] as u32) << (15 - mblr)) | ((x[mlen - 1] as u32) >> mblr)) & 0x7FFF);
        b = ((m[mlen] as u32) << (15 - mblr)) | ((m[mlen - 1] as u32) >> mblr);
    }
    let mut q = divrem16(a, b, None);

    q = MUX(
        EQ(b, a0),
        0x7FFF,
        q.wrapping_sub(1).wrapping_add(q.wrapping_sub(1) >> 31),
    );

    let mut cc: u32 = 0;
    let mut tb: u32 = 1;
    for u in 1..=mlen {
        let mw = m[u] as u32;
        let mut zl = MUL15(mw, q) + cc;
        cc = zl >> 15;
        zl &= 0x7FFF;
        let xw = x[u] as u32;
        let mut nxw = xw.wrapping_sub(zl);
        cc = cc.wrapping_add(nxw >> 31);
        nxw &= 0x7FFF;
        x[u] = nxw as u16;
        tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
    }

    let over = GT(cc, hi);
    let under = !over & (tb | LT(cc, hi));
    br_i15_add(x, m, over);
    br_i15_sub(x, m, under);
}
