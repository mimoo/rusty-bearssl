/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ECDSA signature verification, "i31" implementation, "raw" format
//! (`src/ec/ecdsa_i31_vrfy_raw.c`).

use super::{
    br_ec_impl, br_ec_public_key, br_ecdsa_i31_bits2int, br_secp256r1, br_secp384r1, br_secp521r1,
    BR_EC_secp256r1, BR_EC_secp384r1, BR_EC_secp521r1, BR_MAX_EC_SIZE,
};
use crate::int::{
    br_i31_decode, br_i31_decode_mod, br_i31_encode, br_i31_from_monty, br_i31_iszero,
    br_i31_modpow, br_i31_montymul, br_i31_ninv31, br_i31_sub, br_i31_zero,
};

const I31_LEN: usize = (BR_MAX_EC_SIZE + 61) / 31;
const POINT_LEN: usize = 1 + (((BR_MAX_EC_SIZE + 7) >> 3) << 1);
const FIELD_LEN: usize = (BR_MAX_EC_SIZE + 7) >> 3;

/// see bearssl_ec.h
///
/// IMPORTANT: this code is fit only for curves with a prime order.
pub fn br_ecdsa_i31_vrfy_raw(
    impl_: &br_ec_impl,
    hash: &[u8],
    pk: &br_ec_public_key,
    sig: &[u8],
) -> u32 {
    let mut n = [0u32; I31_LEN];
    let mut r = [0u32; I31_LEN];
    let mut s = [0u32; I31_LEN];
    let mut t1 = [0u32; I31_LEN];
    let mut t2 = [0u32; I31_LEN];
    let mut tx = [0u8; FIELD_LEN];
    let mut ty = [0u8; FIELD_LEN];
    let mut eu = [0u8; POINT_LEN];

    /*
     * If the curve is not supported, then report an error.
     */
    if ((impl_.supported_curves >> pk.curve) & 1) == 0 {
        return 0;
    }

    /*
     * Get the curve parameters (generator and order).
     */
    let cd = match pk.curve {
        BR_EC_secp256r1 => &br_secp256r1,
        BR_EC_secp384r1 => &br_secp384r1,
        BR_EC_secp521r1 => &br_secp521r1,
        _ => return 0,
    };

    /*
     * Signature length must be even.
     */
    let sig_len = sig.len();
    if sig_len & 1 != 0 {
        return 0;
    }
    let rlen = sig_len >> 1;

    /*
     * Public key point must have the proper size for this curve.
     */
    if pk.q.len() != cd.generator.len() {
        return 0;
    }

    /*
     * Get modulus; then decode r and s. They must be lower than the modulus,
     * and s must not be null.
     */
    let nlen = cd.order.len();
    br_i31_decode(&mut n, cd.order, nlen);
    let n0i = br_i31_ninv31(n[1]);
    if br_i31_decode_mod(&mut r, &sig[..rlen], rlen, &n) == 0 {
        return 0;
    }
    if br_i31_decode_mod(&mut s, &sig[rlen..rlen + rlen], rlen, &n) == 0 {
        return 0;
    }
    if br_i31_iszero(&s) != 0 {
        return 0;
    }

    /*
     * Invert s (modular exponentiation), wanting 1/s in Montgomery
     * representation.
     */
    br_i31_from_monty(&mut s, &n, n0i);
    tx[..nlen].copy_from_slice(cd.order);
    tx[nlen - 1] = tx[nlen - 1].wrapping_sub(2);
    {
        let exp = tx;
        br_i31_modpow(&mut s, &exp[..nlen], nlen, &n, n0i, &mut t1, &mut t2);
    }

    /*
     * Truncate the hash to the modulus length (in bits) and reduce it modulo
     * the curve order.
     */
    br_ecdsa_i31_bits2int(&mut t1, hash, hash.len(), n[0]);
    {
        let sub = br_i31_sub(&mut t1, &n, 0) ^ 1;
        br_i31_sub(&mut t1, &n, sub);
    }

    /*
     * Multiply the (truncated, reduced) hash with 1/s, into t2 (encoded ty).
     */
    br_i31_montymul(&mut t2, &t1, &s, &n, n0i);
    br_i31_encode(&mut ty[..nlen], nlen, &t2);

    /*
     * Multiply r with 1/s, into t1 (encoded tx).
     */
    br_i31_montymul(&mut t1, &r, &s, &n, n0i);
    br_i31_encode(&mut tx[..nlen], nlen, &t1);

    /*
     * Compute the point x*Q + y*G.
     */
    let ulen = cd.generator.len();
    eu[..ulen].copy_from_slice(pk.q);
    let mut res = (impl_.muladd)(&mut eu[..ulen], None, &tx[..nlen], &ty[..nlen], cd.curve);

    /*
     * Get the X coordinate, reduce modulo the curve order, compare with r.
     */
    br_i31_zero(&mut t1, n[0]);
    br_i31_decode(&mut t1, &eu[1..1 + (ulen >> 1)], ulen >> 1);
    t1[0] = n[0];
    {
        let sub = br_i31_sub(&mut t1, &n, 0) ^ 1;
        br_i31_sub(&mut t1, &n, sub);
    }
    res &= !br_i31_sub(&mut t1, &r, 1);
    res &= br_i31_iszero(&t1);
    res
}
