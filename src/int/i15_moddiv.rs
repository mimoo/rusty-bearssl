/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_moddiv` (mirrors `src/int/i15_moddiv.c`).
//!
//! Big integers here use a custom format without the one-word header: 15-bit
//! words in 16-bit slots, little-endian, explicit length. Values may be
//! negative (two's complement) and the top word may carry a 16th bit.

use crate::inner::{EQ0, GT, NOT};

/// Negate big integer conditionally over 'len' 15-bit words.
fn cond_negate(a: &mut [u16], len: usize, ctl: u32) {
    let mut cc = ctl;
    let xm = 0x7FFF & ctl.wrapping_neg();
    for k in 0..len {
        let mut aw = a[k] as u32;
        aw = (aw ^ xm).wrapping_add(cc);
        a[k] = (aw & 0x7FFF) as u16;
        cc = (aw >> 15) & 1;
    }
}

/// Finish modular reduction. If neg = 1 then -m <= a < 0; if neg = 0 then
/// 0 <= a < 2*m (top word may use 16 bits). Modulus m must be odd.
fn finish_mod(a: &mut [u16], len: usize, m: &[u16], neg: u32) {
    let mut cc: u32 = 0;
    for k in 0..len {
        let aw = a[k] as u32;
        let mw = m[k] as u32;
        cc = aw.wrapping_sub(mw).wrapping_sub(cc) >> 31;
    }

    let xm = 0x7FFF & neg.wrapping_neg();
    let ym = (neg | (1u32.wrapping_sub(cc))).wrapping_neg();
    cc = neg;
    for k in 0..len {
        let mut aw = a[k] as u32;
        let mw = ((m[k] as u32) ^ xm) & ym;
        aw = aw.wrapping_sub(mw).wrapping_sub(cc);
        a[k] = (aw & 0x7FFF) as u16;
        cc = aw >> 31;
    }
}

/// a <- (a*pa+b*pb)/2^15, b <- (a*qa+b*qb)/2^15 (exact division). Negative
/// results are negated; the returned bits flag which were negated.
fn co_reduce(a: &mut [u16], b: &mut [u16], len: usize, pa: i32, pb: i32, qa: i32, qb: i32) -> u32 {
    let mut cca: i32 = 0;
    let mut ccb: i32 = 0;
    for k in 0..len {
        let wa = a[k] as u32;
        let wb = b[k] as u32;
        let za = wa
            .wrapping_mul(pa as u32)
            .wrapping_add(wb.wrapping_mul(pb as u32))
            .wrapping_add(cca as u32);
        let zb = wa
            .wrapping_mul(qa as u32)
            .wrapping_add(wb.wrapping_mul(qb as u32))
            .wrapping_add(ccb as u32);
        if k > 0 {
            a[k - 1] = (za & 0x7FFF) as u16;
            b[k - 1] = (zb & 0x7FFF) as u16;
        }
        // Sign-extend the 16-bit value (za >> 15) to i32.
        let tta = (za >> 15) as u16;
        let ttb = (zb >> 15) as u16;
        cca = (tta as i16) as i32;
        ccb = (ttb as i16) as i32;
    }
    a[len - 1] = cca as u16;
    b[len - 1] = ccb as u16;
    let nega = (cca as u32) >> 31;
    let negb = (ccb as u32) >> 31;
    cond_negate(a, len, nega);
    cond_negate(b, len, negb);
    nega | (negb << 1)
}

/// a <- (a*pa+b*pb)/2^15 mod m, b <- (a*qa+b*qb)/2^15 mod m. m0i = -1/m[0] mod
/// 2^15.
#[allow(clippy::too_many_arguments)]
fn co_reduce_mod(
    a: &mut [u16],
    b: &mut [u16],
    len: usize,
    pa: i32,
    pb: i32,
    qa: i32,
    qb: i32,
    m: &[u16],
    m0i: u16,
) {
    let mut cca: i32 = 0;
    let mut ccb: i32 = 0;
    let fa = (a[0] as u32)
        .wrapping_mul(pa as u32)
        .wrapping_add((b[0] as u32).wrapping_mul(pb as u32))
        .wrapping_mul(m0i as u32)
        & 0x7FFF;
    let fb = (a[0] as u32)
        .wrapping_mul(qa as u32)
        .wrapping_add((b[0] as u32).wrapping_mul(qb as u32))
        .wrapping_mul(m0i as u32)
        & 0x7FFF;
    for k in 0..len {
        let wa = a[k] as u32;
        let wb = b[k] as u32;
        let za = wa
            .wrapping_mul(pa as u32)
            .wrapping_add(wb.wrapping_mul(pb as u32))
            .wrapping_add((m[k] as u32).wrapping_mul(fa))
            .wrapping_add(cca as u32);
        let zb = wa
            .wrapping_mul(qa as u32)
            .wrapping_add(wb.wrapping_mul(qb as u32))
            .wrapping_add((m[k] as u32).wrapping_mul(fb))
            .wrapping_add(ccb as u32);
        if k > 0 {
            a[k - 1] = (za & 0x7FFF) as u16;
            b[k - 1] = (zb & 0x7FFF) as u16;
        }

        const M: u32 = 1u32 << 16;
        let mut tta = za >> 15;
        let mut ttb = zb >> 15;
        tta = (tta ^ M).wrapping_sub(M);
        ttb = (ttb ^ M).wrapping_sub(M);
        cca = tta as i32;
        ccb = ttb as i32;
    }
    a[len - 1] = cca as u16;
    b[len - 1] = ccb as u16;

    finish_mod(a, len, m, (cca as u32) >> 31);
    finish_mod(b, len, m, (ccb as u32) >> 31);
}

/// Compute x/y mod m, result in x. Returns 1 on success.
pub fn br_i15_moddiv(x: &mut [u16], y: &[u16], m: &[u16], m0i: u16, t: &mut [u16]) -> u32 {
    let len = ((m[0] + 15) >> 4) as usize;

    t[0..len].copy_from_slice(&y[1..1 + len]);
    t[len..2 * len].copy_from_slice(&m[1..1 + len]);
    for w in t[2 * len..3 * len].iter_mut() {
        *w = 0;
    }

    let mut num = ((((m[0] as u32) - ((m[0] as u32) >> 4)) << 1) + 14) as i32;
    while num >= 14 {
        let mut c0: u32 = u32::MAX;
        let mut c1: u32 = u32::MAX;
        let mut a0: u32 = 0;
        let mut a1: u32 = 0;
        let mut b0: u32 = 0;
        let mut b1: u32 = 0;
        let mut j = len;
        while j > 0 {
            j -= 1;
            let aw = t[j] as u32;
            let bw = t[len + j] as u32;
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0xFFFF)) >> 16).wrapping_sub(1);
        }

        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi: u32 = (a0 << 15) + a1;
        let mut b_hi: u32 = (b0 << 15) + b1;
        let mut a_lo: u32 = t[0] as u32;
        let mut b_lo: u32 = t[len] as u32;

        let mut pa: i32 = 1;
        let mut pb: i32 = 0;
        let mut qa: i32 = 0;
        let mut qb: i32 = 1;
        for i in 0..15 {
            let r = GT(a_hi, b_hi);
            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let cab = oa & ob & r;
            let cba = oa & ob & NOT(r);
            let ca = cab | NOT(oa);

            a_lo = a_lo.wrapping_sub(b_lo & cab.wrapping_neg());
            a_hi = a_hi.wrapping_sub(b_hi & cab.wrapping_neg());
            pa -= qa & -(cab as i32);
            pb -= qb & -(cab as i32);
            b_lo = b_lo.wrapping_sub(a_lo & cba.wrapping_neg());
            b_hi = b_hi.wrapping_sub(a_hi & cba.wrapping_neg());
            qa -= pa & -(cba as i32);
            qb -= pb & -(cba as i32);

            a_lo = a_lo.wrapping_add(a_lo & ca.wrapping_sub(1));
            pa += pa & ((ca as i32) - 1);
            pb += pb & ((ca as i32) - 1);
            a_hi ^= (a_hi ^ (a_hi >> 1)) & ca.wrapping_neg();
            b_lo = b_lo.wrapping_add(b_lo & ca.wrapping_neg());
            qa += qa & -(ca as i32);
            qb += qb & -(ca as i32);
            b_hi ^= (b_hi ^ (b_hi >> 1)) & ca.wrapping_sub(1);
        }

        let r = {
            let (a_slice, rest) = t.split_at_mut(len);
            let (b_slice, _v_slice) = rest.split_at_mut(len);
            co_reduce(a_slice, b_slice, len, pa, pb, qa, qb)
        };
        pa -= pa * (((r & 1) << 1) as i32);
        pb -= pb * (((r & 1) << 1) as i32);
        qa -= qa * ((r & 2) as i32);
        qb -= qb * ((r & 2) as i32);
        {
            let (u_slice, _) = x.split_at_mut(1 + len);
            let v_slice = &mut t[2 * len..3 * len];
            co_reduce_mod(
                &mut u_slice[1..1 + len],
                v_slice,
                len,
                pa,
                pb,
                qa,
                qb,
                &m[1..],
                m0i,
            );
        }

        num -= 14;
    }

    let mut r = (t[0] as u32 | t[len] as u32) ^ 1;
    x[1] |= t[2 * len];
    for k in 1..len {
        r |= t[k] as u32 | t[len + k] as u32;
        x[1 + k] |= t[2 * len + k];
    }
    EQ0(r as i32)
}
