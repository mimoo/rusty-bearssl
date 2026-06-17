/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_moddiv` (mirrors `src/int/i31_moddiv.c`).
//!
//! In this file we handle big integers with a custom format, i.e. without the
//! usual one-word header. Value is split into 31-bit words, each stored in a
//! 32-bit slot (top bit zero) in little-endian order. The length (in words) is
//! provided explicitly. In some cases the value can be negative (two's
//! complement) and the top word may have a 32nd bit.

use crate::inner::{EQ0, NOT};

/// Negate big integer conditionally over 'len' 31-bit words.
fn cond_negate(a: &mut [u32], len: usize, ctl: u32) {
    let mut cc = ctl;
    let xm = ctl.wrapping_neg() >> 1;
    for k in 0..len {
        let mut aw = a[k];
        aw = (aw ^ xm).wrapping_add(cc);
        a[k] = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/// Finish modular reduction. If neg = 1 then -m <= a < 0; if neg = 0 then
/// 0 <= a < 2*m (top word may use 32 bits). Modulus m must be odd.
fn finish_mod(a: &mut [u32], len: usize, m: &[u32], neg: u32) {
    let mut cc: u32 = 0;
    for k in 0..len {
        let aw = a[k];
        let mw = m[k];
        cc = aw.wrapping_sub(mw).wrapping_sub(cc) >> 31;
    }

    let xm = neg.wrapping_neg() >> 1;
    let ym = (neg | (1u32.wrapping_sub(cc))).wrapping_neg();
    cc = neg;
    for k in 0..len {
        let mut aw = a[k];
        let mw = (m[k] ^ xm) & ym;
        aw = aw.wrapping_sub(mw).wrapping_sub(cc);
        a[k] = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/// a <- (a*pa+b*pb)/2^31, b <- (a*qa+b*qb)/2^31 (exact division). Negative
/// results are negated; the returned bits flag which were negated.
fn co_reduce(a: &mut [u32], b: &mut [u32], len: usize, pa: i64, pb: i64, qa: i64, qb: i64) -> u32 {
    let mut cca: i64 = 0;
    let mut ccb: i64 = 0;
    for k in 0..len {
        let wa = a[k];
        let wb = b[k];
        let za = (wa as u64)
            .wrapping_mul(pa as u64)
            .wrapping_add((wb as u64).wrapping_mul(pb as u64))
            .wrapping_add(cca as u64);
        let zb = (wa as u64)
            .wrapping_mul(qa as u64)
            .wrapping_add((wb as u64).wrapping_mul(qb as u64))
            .wrapping_add(ccb as u64);
        if k > 0 {
            a[k - 1] = (za as u32) & 0x7FFFFFFF;
            b[k - 1] = (zb as u32) & 0x7FFFFFFF;
        }

        const M: u64 = 1u64 << 32;
        let mut tta = za >> 31;
        let mut ttb = zb >> 31;
        tta = (tta ^ M).wrapping_sub(M);
        ttb = (ttb ^ M).wrapping_sub(M);
        cca = tta as i64;
        ccb = ttb as i64;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    let nega = ((cca as u64) >> 63) as u32;
    let negb = ((ccb as u64) >> 63) as u32;
    cond_negate(a, len, nega);
    cond_negate(b, len, negb);
    nega | (negb << 1)
}

/// a <- (a*pa+b*pb)/2^31 mod m, b <- (a*qa+b*qb)/2^31 mod m. m0i = -1/m[0] mod
/// 2^31.
#[allow(clippy::too_many_arguments)]
fn co_reduce_mod(
    a: &mut [u32],
    b: &mut [u32],
    len: usize,
    pa: i64,
    pb: i64,
    qa: i64,
    qb: i64,
    m: &[u32],
    m0i: u32,
) {
    let mut cca: i64 = 0;
    let mut ccb: i64 = 0;
    let fa = (a[0]
        .wrapping_mul(pa as u32)
        .wrapping_add(b[0].wrapping_mul(pb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFFFFFF;
    let fb = (a[0]
        .wrapping_mul(qa as u32)
        .wrapping_add(b[0].wrapping_mul(qb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFFFFFF;
    for k in 0..len {
        let wa = a[k];
        let wb = b[k];
        let za = (wa as u64)
            .wrapping_mul(pa as u64)
            .wrapping_add((wb as u64).wrapping_mul(pb as u64))
            .wrapping_add((m[k] as u64).wrapping_mul(fa as u64))
            .wrapping_add(cca as u64);
        let zb = (wa as u64)
            .wrapping_mul(qa as u64)
            .wrapping_add((wb as u64).wrapping_mul(qb as u64))
            .wrapping_add((m[k] as u64).wrapping_mul(fb as u64))
            .wrapping_add(ccb as u64);
        if k > 0 {
            a[k - 1] = (za as u32) & 0x7FFFFFFF;
            b[k - 1] = (zb as u32) & 0x7FFFFFFF;
        }

        const M: u64 = 1u64 << 32;
        let mut tta = za >> 31;
        let mut ttb = zb >> 31;
        tta = (tta ^ M).wrapping_sub(M);
        ttb = (ttb ^ M).wrapping_sub(M);
        cca = tta as i64;
        ccb = ttb as i64;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    finish_mod(a, len, m, ((cca as u64) >> 63) as u32);
    finish_mod(b, len, m, ((ccb as u64) >> 63) as u32);
}

/// Compute x/y mod m, result in x. x and y must be in [0, m-1] with the same
/// announced bit length as m. Modulus m must be odd. m0i = -1/m mod 2^31. t
/// must hold at least three integers the size of m. Returns 1 on success.
pub fn br_i31_moddiv(x: &mut [u32], y: &[u32], m: &[u32], m0i: u32, t: &mut [u32]) -> u32 {
    let len = ((m[0] + 31) >> 5) as usize;

    // a = t[0..len], b = t[len..2len], v = t[2len..3len]. u = x[1..].
    // Initialise these regions.
    t[0..len].copy_from_slice(&y[1..1 + len]);
    t[len..2 * len].copy_from_slice(&m[1..1 + len]);
    for w in t[2 * len..3 * len].iter_mut() {
        *w = 0;
    }

    let mut num = (((m[0] - (m[0] >> 5)) << 1) + 30) as i64;
    while num >= 30 {
        let mut c0: u32 = u32::MAX;
        let mut c1: u32 = u32::MAX;
        let mut a0: u32 = 0;
        let mut a1: u32 = 0;
        let mut b0: u32 = 0;
        let mut b1: u32 = 0;
        let mut j = len;
        while j > 0 {
            j -= 1;
            let aw = t[j];
            let bw = t[len + j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0x7FFFFFFF)) >> 31).wrapping_sub(1);
        }

        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi: u64 = ((a0 as u64) << 31) + a1 as u64;
        let mut b_hi: u64 = ((b0 as u64) << 31) + b1 as u64;
        let mut a_lo: u32 = t[0];
        let mut b_lo: u32 = t[len];

        let mut pa: i64 = 1;
        let mut pb: i64 = 0;
        let mut qa: i64 = 0;
        let mut qb: i64 = 1;
        for i in 0..31 {
            let rz = b_hi.wrapping_sub(a_hi);
            let r = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;

            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let cab = oa & ob & r;
            let cba = oa & ob & NOT(r);
            let ca = cab | NOT(oa);

            a_lo = a_lo.wrapping_sub(b_lo & cab.wrapping_neg());
            a_hi = a_hi.wrapping_sub(b_hi & (cab as u64).wrapping_neg());
            pa -= qa & -(cab as i64);
            pb -= qb & -(cab as i64);
            b_lo = b_lo.wrapping_sub(a_lo & cba.wrapping_neg());
            b_hi = b_hi.wrapping_sub(a_hi & (cba as u64).wrapping_neg());
            qa -= pa & -(cba as i64);
            qb -= pb & -(cba as i64);

            a_lo = a_lo.wrapping_add(a_lo & ca.wrapping_sub(1));
            pa += pa & ((ca as i64) - 1);
            pb += pb & ((ca as i64) - 1);
            a_hi ^= (a_hi ^ (a_hi >> 1)) & (ca as u64).wrapping_neg();
            b_lo = b_lo.wrapping_add(b_lo & ca.wrapping_neg());
            qa += qa & -(ca as i64);
            qb += qb & -(ca as i64);
            b_hi ^= (b_hi ^ (b_hi >> 1)) & ((ca as u64).wrapping_sub(1));
        }

        let r = {
            let (a_slice, rest) = t.split_at_mut(len);
            let (b_slice, _v_slice) = rest.split_at_mut(len);
            co_reduce(a_slice, b_slice, len, pa, pb, qa, qb)
        };
        pa -= pa * (((r & 1) << 1) as i64);
        pb -= pb * (((r & 1) << 1) as i64);
        qa -= qa * ((r & 2) as i64);
        qb -= qb * ((r & 2) as i64);
        // co_reduce_mod(u, v, len, ..., m + 1, m0i): u = x[1..], v = t[2len..].
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

        num -= 30;
    }

    // Now one of a/b is 0 and the other holds the GCD. Result valid iff GCD=1.
    let mut r = (t[0] | t[len]) ^ 1;
    x[1] |= t[2 * len];
    for k in 1..len {
        r |= t[k] | t[len + k];
        x[1 + k] |= t[2 * len + k];
    }
    EQ0(r as i32)
}
