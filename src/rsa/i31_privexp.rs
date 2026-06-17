/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_compute_privexp` (mirrors `src/rsa/rsa_i31_privexp.c`).

use super::{br_rsa_private_key, BR_MAX_RSA_FACTOR};
use crate::inner::{GT, NOT};
use crate::int::{br_divrem, br_i31_bit_length, br_i31_decode, br_i31_encode, br_i31_mulacc, br_i31_zero};

/// see bearssl_rsa.h
///
/// Recompute the private exponent `d = 1/e mod (p-1)(q-1)`. If `d` is `Some`,
/// it is encoded there. Returns the modulus length in bytes (0 on error).
pub fn br_rsa_i31_compute_privexp(
    d: Option<&mut [u8]>,
    sk: &br_rsa_private_key,
    e: u32,
) -> usize {
    let mut tmp = [0u32; 4 * ((BR_MAX_RSA_FACTOR + 30) / 31) + 12];

    // Check that e is correct.
    if e < 3 || (e & 1) == 0 {
        return 0;
    }

    // Check lengths of p and q, and that they are both odd.
    let mut poff = 0usize;
    let mut plen_b = sk.p.len();
    while plen_b > 0 && sk.p[poff] == 0 {
        poff += 1;
        plen_b -= 1;
    }
    if plen_b < 5 || plen_b > (BR_MAX_RSA_FACTOR / 8) || (sk.p[poff + plen_b - 1] & 1) != 1 {
        return 0;
    }
    let mut qoff = 0usize;
    let mut qlen_b = sk.q.len();
    while qlen_b > 0 && sk.q[qoff] == 0 {
        qoff += 1;
        qlen_b -= 1;
    }
    if qlen_b < 5 || qlen_b > (BR_MAX_RSA_FACTOR / 8) || (sk.q[qoff + qlen_b - 1] & 1) != 1 {
        return 0;
    }
    let pbuf = &sk.p[poff..poff + plen_b];
    let qbuf = &sk.q[qoff..qoff + qlen_b];

    // Output length is that of the modulus.
    let dlen = ((sk.n_bitlen + 7) >> 3) as usize;
    let d = match d {
        None => return dlen,
        Some(d) => d,
    };

    // p = tmp; q = p + 1 + plen.
    br_i31_decode(&mut tmp[..], pbuf, plen_b);
    let plen = ((tmp[0] + 31) >> 5) as usize;
    let q_off = 1 + plen;
    br_i31_decode(&mut tmp[q_off..], qbuf, qlen_b);
    let qlen = ((tmp[q_off] + 31) >> 5) as usize;

    // Compute phi = (p-1)*(q-1).
    tmp[1] -= 1; // p[1]--
    tmp[q_off + 1] -= 1; // q[1]--
    let phi_off = q_off + 1 + qlen;
    {
        let p_hdr = tmp[0];
        br_i31_zero(&mut tmp[phi_off..], p_hdr);
        // mulacc(phi, p, q): phi = [phi_off,..), p = [0, q_off), q = [q_off, phi_off)
        let (head, phi) = tmp.split_at_mut(phi_off);
        let (p, q) = head.split_at_mut(q_off);
        br_i31_mulacc(phi, p, q);
    }
    // Move phi to tmp[0..], readjust its announced bit length.
    let mut len = ((tmp[phi_off] + 31) >> 5) as usize;
    tmp.copy_within(phi_off..phi_off + 1 + len, 0);
    // phi = tmp; recompute its header from the true bit length.
    let bl = br_i31_bit_length(&tmp[1..1 + len], len);
    tmp[0] = bl;
    len = ((tmp[0] + 31) >> 5) as usize;

    // Divide phi by e. Quotient k overwrites phi.
    let mut r: u32 = 0;
    {
        let mut u = len;
        while u >= 1 {
            let hi = r >> 1;
            let lo = (r << 31) + tmp[u];
            tmp[u] = br_divrem(hi, lo, e, &mut r);
            u -= 1;
        }
    }
    if r == 0 {
        return 0;
    }
    // k = phi = tmp.

    // Compute u, v such that u*e - v*r = GCD(e,r), via binary GCD.
    let mut a = e;
    let mut b = r;
    let mut u0: u32 = 1;
    let mut v0: u32 = 0;
    let mut u1: u32 = r;
    let mut v1: u32 = e - 1;
    let hr = (r + 1) >> 1;
    let he = (e >> 1) + 1;
    for _ in 0..62 {
        let oa = a & 1;
        let ob = b & 1;
        let agtb = GT(a, b);
        let bgta = GT(b, a);

        let sab = oa & ob & agtb;
        let sba = oa & ob & bgta;

        // a <- a-b, u0 <- u0-u1, v0 <- v0-v1
        let mut ctl = GT(v1, v0);
        a = a.wrapping_sub(b & sab.wrapping_neg());
        u0 = u0.wrapping_sub((u1.wrapping_sub(r & ctl.wrapping_neg())) & sab.wrapping_neg());
        v0 = v0.wrapping_sub((v1.wrapping_sub(e & ctl.wrapping_neg())) & sab.wrapping_neg());

        // b <- b-a, u1 <- u1-u0 mod r, v1 <- v1-v0 mod e
        ctl = GT(v0, v1);
        b = b.wrapping_sub(a & sba.wrapping_neg());
        u1 = u1.wrapping_sub((u0.wrapping_sub(r & ctl.wrapping_neg())) & sba.wrapping_neg());
        v1 = v1.wrapping_sub((v0.wrapping_sub(e & ctl.wrapping_neg())) & sba.wrapping_neg());

        let da = NOT(oa) | sab;
        let db = (oa & NOT(ob)) | sba;

        // a <- a/2, u0 <- u0/2, v0 <- v0/2
        ctl = v0 & 1;
        a ^= (a ^ (a >> 1)) & da.wrapping_neg();
        u0 ^= (u0 ^ ((u0 >> 1).wrapping_add(hr & ctl.wrapping_neg()))) & da.wrapping_neg();
        v0 ^= (v0 ^ ((v0 >> 1).wrapping_add(he & ctl.wrapping_neg()))) & da.wrapping_neg();

        // b <- b/2, u1 <- u1/2 mod r, v1 <- v1/2 mod e
        ctl = v1 & 1;
        b ^= (b ^ (b >> 1)) & db.wrapping_neg();
        u1 ^= (u1 ^ ((u1 >> 1).wrapping_add(hr & ctl.wrapping_neg()))) & db.wrapping_neg();
        v1 ^= (v1 ^ ((v1 >> 1).wrapping_add(he & ctl.wrapping_neg()))) & db.wrapping_neg();
    }

    // GCD must be 1.
    if a != 1 {
        return 0;
    }

    // d = u0 + v0*k. k is tmp, with announced bit length that of phi.
    // m = k + 1 + len; z = m + 3.
    let m_off = 1 + len;
    let z_off = m_off + 3;
    tmp[m_off] = (1 << 5) + 1; // bit length 32 bits, encoded
    tmp[m_off + 1] = v0 & 0x7FFFFFFF;
    tmp[m_off + 2] = v0 >> 31;
    {
        let k_hdr = tmp[0];
        br_i31_zero(&mut tmp[z_off..], k_hdr);
        tmp[z_off + 1] = u0 & 0x7FFFFFFF;
        tmp[z_off + 2] = u0 >> 31;
        // mulacc(z, k, m): z = [z_off,..), k = [0, m_off), m = [m_off, z_off)
        let (head, z) = tmp.split_at_mut(z_off);
        let (k, m) = head.split_at_mut(m_off);
        br_i31_mulacc(z, k, m);
    }

    br_i31_encode(d, dlen, &tmp[z_off..]);
    dlen
}
