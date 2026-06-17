/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_compute_modulus` (mirrors `src/rsa/rsa_i31_modulus.c`).

use super::{br_rsa_private_key, BR_MAX_RSA_SIZE};
use crate::int::{br_i31_decode, br_i31_encode, br_i31_mulacc, br_i31_zero};

/// see bearssl_rsa.h
///
/// Recompute the RSA modulus `n = p*q` from the private key. If `n` is `Some`,
/// the modulus is encoded there. Returns the modulus length in bytes (0 on
/// error / oversized factors).
pub fn br_rsa_i31_compute_modulus(n: Option<&mut [u8]>, sk: &br_rsa_private_key) -> usize {
    let mut tmp = [0u32; 4 * (((BR_MAX_RSA_SIZE / 2) + 30) / 31) + 5];

    // Compute actual bytes for p and q.
    let mut poff = 0usize;
    let mut plen_b = sk.p.len();
    while plen_b > 0 && sk.p[poff] == 0 {
        poff += 1;
        plen_b -= 1;
    }
    let mut qoff = 0usize;
    let mut qlen_b = sk.q.len();
    while qlen_b > 0 && sk.q[qoff] == 0 {
        qoff += 1;
        qlen_b -= 1;
    }
    let pbuf = &sk.p[poff..poff + plen_b];
    let qbuf = &sk.q[qoff..qoff + qlen_b];

    // `toff` tracks the moving `t` pointer (word offset into tmp). `tlen` is the
    // remaining word count from `toff`.
    let mut toff = 0usize;
    let mut tlen = tmp.len();

    // Decode p.
    if (31 * tlen) < (plen_b << 3) + 31 {
        return 0;
    }
    br_i31_decode(&mut tmp[toff..], pbuf, plen_b);
    let p_off = toff;
    let plen = ((tmp[p_off] + 63) >> 5) as usize;
    toff += plen;
    tlen -= plen;

    // Decode q.
    if (31 * tlen) < (qlen_b << 3) + 31 {
        return 0;
    }
    br_i31_decode(&mut tmp[toff..], qbuf, qlen_b);
    let q_off = toff;
    let qlen = ((tmp[q_off] + 63) >> 5) as usize;
    toff += qlen;
    tlen -= qlen;

    // Need room for the modulus.
    if tlen < (plen + qlen + 1) {
        return 0;
    }

    let nlen = ((sk.n_bitlen + 7) >> 3) as usize;
    if let Some(n) = n {
        let p_hdr = tmp[p_off]; // p[0]
        br_i31_zero(&mut tmp[toff..], p_hdr);
        // mulacc(t, p, q): t = [toff,..), p = [p_off, q_off), q = [q_off, toff)
        {
            let (head, t) = tmp.split_at_mut(toff);
            let p = &head[p_off..q_off];
            let q = &head[q_off..toff];
            br_i31_mulacc(t, p, q);
        }
        br_i31_encode(n, nlen, &tmp[toff..]);
    }
    nlen
}
