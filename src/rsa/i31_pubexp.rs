/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_compute_pubexp` (mirrors `src/rsa/rsa_i31_pubexp.c`).

use super::{br_rsa_private_key, BR_MAX_RSA_FACTOR};
use crate::inner::{EQ, LT, NOT};
use crate::int::{
    br_i31_bit_length, br_i31_decode, br_i31_moddiv, br_i31_ninv31, br_i31_rshift, br_i31_sub,
    br_i31_zero,
};

/// Recompute public exponent from factor p and reduced private exponent dp.
fn get_pubexp(pbuf: &[u8], dpbuf: &[u8]) -> u32 {
    let mut tmp = [0u32; 6 * ((BR_MAX_RSA_FACTOR + 61) / 31)];

    // Compute actual factor length (bytes) and check size constraints.
    let mut poff = 0usize;
    let mut plen = pbuf.len();
    while plen > 0 && pbuf[poff] == 0 {
        poff += 1;
        plen -= 1;
    }
    if plen == 0 || plen < 5 || plen > (BR_MAX_RSA_FACTOR / 8) {
        return 0;
    }
    let pbuf = &pbuf[poff..poff + plen];

    // Compute actual reduced exponent length and check it is not longer than p.
    let mut dpoff = 0usize;
    let mut dplen = dpbuf.len();
    while dplen > 0 && dpbuf[dpoff] == 0 {
        dpoff += 1;
        dplen -= 1;
    }
    let dpbuf = &dpbuf[dpoff..dpoff + dplen];
    if dplen > plen || dplen == 0 || (dplen == plen && dpbuf[0] > pbuf[0]) {
        return 0;
    }

    // Verify p = 3 mod 4 and dp odd.
    if (pbuf[plen - 1] & 3) != 3 || (dpbuf[dplen - 1] & 1) != 1 {
        return 0;
    }

    // Decode p and compute (p-1)/2.
    br_i31_decode(&mut tmp[..], pbuf, plen);
    let len = ((tmp[0] + 63) >> 5) as usize;
    br_i31_rshift(&mut tmp[..], 1);

    // Decode dp at offset `len`; clear that region first, then fix its header to
    // match p's.
    {
        let dp = &mut tmp[len..2 * len];
        for w in dp.iter_mut() {
            *w = 0;
        }
        br_i31_decode(dp, dpbuf, dplen);
    }
    let p_hdr = tmp[0];
    tmp[len] = p_hdr; // dp[0] = p[0]

    // Subtract (p-1)/2 from dp if necessary: sub(dp, p, NOT(sub(dp, p, 0))).
    {
        let ctl0 = {
            let (p, dp) = tmp.split_at_mut(len);
            br_i31_sub(dp, p, 0)
        };
        let (p, dp) = tmp.split_at_mut(len);
        br_i31_sub(dp, p, NOT(ctl0));
    }

    // If another subtraction is needed, the value was invalid.
    {
        let (p, dp) = tmp.split_at_mut(len);
        if br_i31_sub(dp, p, 0) == 0 {
            return 0;
        }
    }

    // Invert dp modulo (p-1)/2. x = dp + len.
    let p1 = tmp[1];
    {
        let x = &mut tmp[2 * len..3 * len];
        br_i31_zero(x, p_hdr);
        x[1] = 1;
    }
    {
        // moddiv(x, dp, p, ninv31(p[1]), x + len)
        // x = [2*len, 3*len), dp = [len, 2*len), p = [0, len), scratch = [3*len,..)
        let m0i = br_i31_ninv31(p1);
        let (head, scratch) = tmp.split_at_mut(3 * len);
        let (p, rest) = head.split_at_mut(len);
        let (dp, x) = rest.split_at_mut(len);
        if br_i31_moddiv(x, dp, p, m0i, scratch) == 0 {
            return 0;
        }
    }

    // Recover e = x[1] | (x[2] << 31); reject if length > 32 bits or even.
    let x1 = tmp[2 * len + 1];
    let x2 = tmp[2 * len + 2];
    let mut e = x1 | (x2 << 31);
    let bl = {
        let x = &tmp[2 * len..3 * len];
        br_i31_bit_length(&x[1..], len - 1)
    };
    e &= (LT(bl, 34)).wrapping_neg();
    e &= (e & 1).wrapping_neg();
    e
}

/// see bearssl_rsa.h
pub fn br_rsa_i31_compute_pubexp(sk: &br_rsa_private_key) -> u32 {
    // Get the public exponent from both p and q; correct iff they match.
    let ep = get_pubexp(sk.p, sk.dp);
    let eq = get_pubexp(sk.q, sk.dq);
    ep & EQ(ep, eq).wrapping_neg()
}
