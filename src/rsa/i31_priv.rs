/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_private` (mirrors `src/rsa/rsa_i31_priv.c`).

use super::{br_rsa_private_key, BR_MAX_RSA_FACTOR};
use crate::int::{
    br_i31_add, br_i31_decode, br_i31_decode_reduce, br_i31_encode, br_i31_modpow_opt,
    br_i31_montymul, br_i31_mulacc, br_i31_ninv31, br_i31_reduce, br_i31_sub, br_i31_to_monty,
    br_i31_zero,
};

const U: usize = 2 + ((BR_MAX_RSA_FACTOR + 30) / 31);
const TLEN: usize = 8 * U;

/// Return two disjoint mutable subslices of `buf` starting at word offsets `a`
/// and `b` (with `a < b`); the first spans `[a, b)` extended to `buf.len()`
/// only up to the second's start, the second spans `[b, buf.len())`.
fn split2(buf: &mut [u32], a: usize, b: usize) -> (&mut [u32], &mut [u32]) {
    debug_assert!(a < b);
    let (lo, hi) = buf.split_at_mut(b);
    (&mut lo[a..], hi)
}

/// see bearssl_rsa.h
///
/// RSA private-key operation (CRT): replace `x` with `x^d mod n`. Returns 1 on
/// success, 0 on error (invalid key/operand).
pub fn br_rsa_i31_private(x: &mut [u8], sk: &br_rsa_private_key) -> u32 {
    let mut tmp = [0u32; 1 + TLEN];

    // Compute actual lengths of p and q, in bytes (not secret).
    let mut poff = 0usize;
    let mut plen = sk.p.len();
    while plen > 0 && sk.p[poff] == 0 {
        poff += 1;
        plen -= 1;
    }
    let mut qoff = 0usize;
    let mut qlen = sk.q.len();
    while qlen > 0 && sk.q[qoff] == 0 {
        qoff += 1;
        qlen -= 1;
    }
    let p = &sk.p[poff..poff + plen];
    let q = &sk.q[qoff..qoff + qlen];

    // Compute the maximum factor length, in words.
    let mut z = (if plen > qlen { plen } else { qlen } as isize) << 3;
    let mut fwlen = 1usize;
    while z > 0 {
        z -= 31;
        fwlen += 1;
    }
    // Round up to an even number.
    fwlen += fwlen & 1;

    // We need to fit at least 6 values in the stack buffer.
    if 6 * fwlen > TLEN {
        return 0;
    }

    // Compute modulus length (in bytes).
    let xlen = ((sk.n_bitlen + 7) >> 3) as usize;

    // Word offsets of the working values inside tmp (all in units of fwlen).
    let o_mq = 0; // mq = tmp
    let o1 = fwlen; // mq + fwlen
    let o2 = 2 * fwlen; // mq + 2*fwlen
    let o3 = 3 * fwlen; // mq + 3*fwlen
    let o4 = 4 * fwlen; // mq + 4*fwlen
    let o5 = 5 * fwlen; // mq + 5*fwlen

    // Decode q into mq (tmp[0..]).
    br_i31_decode(&mut tmp[o_mq..], q, qlen);

    // Decode p into t1 = mq + fwlen.
    br_i31_decode(&mut tmp[o1..], p, plen);

    // Compute the modulus (product of the two factors) to compare with the
    // source value. t2 = mq + 2*fwlen.
    {
        let mq0 = tmp[o_mq]; // header word of mq
        br_i31_zero(&mut tmp[o2..], mq0);
        // mulacc(t2, mq, t1): all three distinct.
        let (head, t2) = tmp.split_at_mut(o2);
        let (mq, t1) = head.split_at_mut(o1);
        br_i31_mulacc(t2, mq, t1);
    }

    // Encode the modulus into t3 = mq + 4*fwlen, then compare with x[] bytes,
    // computing the borrow as the error accumulator r.
    let mut r: u32;
    {
        let t2_words = (1 + ((tmp[o2] + 63) >> 5)) as usize;
        let t2: Vec<u32> = tmp[o2..o2 + t2_words].to_vec();
        // Encode into a byte buffer of length xlen (t3 in C is reinterpreted as
        // bytes); we use a scratch byte buffer.
        let mut t3 = vec![0u8; xlen];
        br_i31_encode(&mut t3, xlen, &t2);
        let mut u = xlen;
        let mut rr: u32 = 0;
        while u > 0 {
            u -= 1;
            let wn = t3[u] as u32;
            let wx = x[u] as u32;
            rr = (wx.wrapping_sub(wn + rr) >> 8) & 1;
        }
        r = rr;
    }

    // Move the decoded p to mp = mq + 2*fwlen.
    {
        let (head, mp) = tmp.split_at_mut(o2);
        let t1 = &head[o1..o1 + fwlen];
        mp[..fwlen].copy_from_slice(t1);
    }

    // Compute s2 = x^dq mod q. q is mq; q0i = ninv31(mq[1]). s2 = mq + fwlen.
    let q0i = br_i31_ninv31(tmp[o_mq + 1]);
    {
        // decode_reduce(s2, x, xlen, mq): s2 = mq+fwlen, mq = mq+0.
        let (mq, s2) = split2(&mut tmp, o_mq, o1);
        br_i31_decode_reduce(s2, x, xlen, mq);
    }
    {
        // modpow_opt(s2, dq, mq, q0i, mq+3*fwlen, TLEN-3*fwlen)
        // s2 = [o1, o2), mq = [o_mq, o1), scratch = [o3, end)
        let (head, scratch) = tmp.split_at_mut(o3);
        let (mq, s2) = head.split_at_mut(o1);
        r &= br_i31_modpow_opt(s2, sk.dq, sk.dq.len(), mq, q0i, scratch, TLEN - 3 * fwlen);
    }

    // Compute s1 = x^dp mod p. p is mp = mq + 2*fwlen; p0i = ninv31(mp[1]).
    // s1 = mq + 3*fwlen.
    let p0i = br_i31_ninv31(tmp[o2 + 1]);
    {
        // decode_reduce(s1, x, xlen, mp): s1 = [o3,..), mp = [o2, o3)
        let (mp, s1) = split2(&mut tmp, o2, o3);
        br_i31_decode_reduce(s1, x, xlen, mp);
    }
    {
        // modpow_opt(s1, dp, mp, p0i, mq+4*fwlen, TLEN-4*fwlen)
        // s1 = [o3, o4), mp = [o2, o3), scratch = [o4, end)
        let (head, scratch) = tmp.split_at_mut(o4);
        let (mp_region, s1) = head.split_at_mut(o3);
        let mp = &mp_region[o2..];
        r &= br_i31_modpow_opt(s1, sk.dp, sk.dp.len(), mp, p0i, scratch, TLEN - 4 * fwlen);
    }

    // Compute h = (s1 - s2)*(1/q) mod p.
    // t1 = mq + 4*fwlen; t2 = mq + 5*fwlen.
    {
        // reduce(t2, s2, mp): t2 = [o5,..), s2 = [o1, o2), mp = [o2, o3)
        // t2 and (s2,mp) are disjoint; s2 and mp are adjacent within [o1, o3).
        let (head, t2) = tmp.split_at_mut(o5);
        let s2 = &head[o1..o2];
        let mp = &head[o2..o3];
        br_i31_reduce(t2, s2, mp);
    }
    {
        // add(s1, mp, sub(s1, t2, 1)):
        // s1 = [o3, o4), mp = [o2, o3), t2 = [o5,..)
        // First: sub(s1, t2, 1) -> ctl
        let ctl = {
            let (head, t2) = tmp.split_at_mut(o5);
            let s1 = &mut head[o3..o4];
            br_i31_sub(s1, t2, 1)
        };
        // Then: add(s1, mp, ctl)
        let (head, s1) = tmp.split_at_mut(o3);
        let mp = &head[o2..o3];
        let s1 = &mut s1[..fwlen];
        br_i31_add(s1, mp, ctl);
    }
    {
        // to_monty(s1, mp): s1 = [o3, o4), mp = [o2, o3)
        let (mp, s1) = split2(&mut tmp, o2, o3);
        br_i31_to_monty(s1, mp);
    }
    {
        // decode_reduce(t1, iq, mp): t1 = [o4, o5), mp = [o2, o3)
        let (mp, t1) = split2(&mut tmp, o2, o4);
        br_i31_decode_reduce(t1, sk.iq, sk.iq.len(), mp);
    }
    {
        // montymul(t2, s1, t1, mp, p0i):
        // t2 = [o5,..), s1 = [o3, o4), t1 = [o4, o5), mp = [o2, o3)
        let (head, t2) = tmp.split_at_mut(o5);
        let mp = &head[o2..o3];
        let s1 = &head[o3..o4];
        let t1 = &head[o4..o5];
        br_i31_montymul(t2, s1, t1, mp, p0i);
    }

    // h is now in t2 = mq + 5*fwlen. Compute s = s2 + q*h.
    // t3 reuses s2 = mq + fwlen. mq is at offset 0, t2 at o5.
    {
        // mulacc(t3, mq, t2): t3 = s2 = mq + fwlen. In C, t3 reuses the s2 slot
        // (the mp/s1/t1 slots above it are no longer needed). The product
        // s = s2 + q*h has full modulus size; mulacc accumulates onto d, so the
        // words of t3 above s2 must be zero. Clear [o2, o5) (h lives at o5).
        for w in tmp[o2..o5].iter_mut() {
            *w = 0;
        }
        let (head, t2) = tmp.split_at_mut(o5);
        let (mq, t3) = head.split_at_mut(o1); // t3 = [o1, o5)
        br_i31_mulacc(t3, mq, t2);
    }

    // Encode the result from t3 = s2 = mq + fwlen.
    {
        let t3 = &tmp[o1..];
        br_i31_encode(x, xlen, t3);
    }

    p0i & q0i & r
}
