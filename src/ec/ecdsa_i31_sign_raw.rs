/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ECDSA signature generation, "i31" implementation, "raw" format
//! (`src/ec/ecdsa_i31_sign_raw.c`).

use super::{
    br_ec_impl, br_ec_private_key, br_ecdsa_i31_bits2int, br_secp256r1, br_secp384r1, br_secp521r1,
    BR_EC_secp256r1, BR_EC_secp384r1, BR_EC_secp521r1, BR_MAX_EC_SIZE,
};
use crate::hash::{br_hash_class, BR_HASHDESC_OUT_MASK, BR_HASHDESC_OUT_OFF};
use crate::int::{
    br_i31_add, br_i31_decode, br_i31_decode_mod, br_i31_encode, br_i31_from_monty, br_i31_iszero,
    br_i31_modpow, br_i31_montymul, br_i31_ninv31, br_i31_sub, br_i31_zero,
};
use crate::rand::{br_hmac_drbg_context, br_hmac_drbg_generate, br_hmac_drbg_init};

const I31_LEN: usize = (BR_MAX_EC_SIZE + 61) / 31;
const POINT_LEN: usize = 1 + (((BR_MAX_EC_SIZE + 7) >> 3) << 1);
const ORDER_LEN: usize = (BR_MAX_EC_SIZE + 7) >> 3;

/// see bearssl_ec.h
///
/// IMPORTANT: this code is fit only for curves with a prime order (P-256/384/521).
pub fn br_ecdsa_i31_sign_raw(
    impl_: &br_ec_impl,
    hf: &'static br_hash_class,
    hash_value: &[u8],
    sk: &br_ec_private_key,
    sig: &mut [u8],
) -> usize {
    let mut n = [0u32; I31_LEN];
    let mut r = [0u32; I31_LEN];
    let mut s = [0u32; I31_LEN];
    let mut x = [0u32; I31_LEN];
    let mut m = [0u32; I31_LEN];
    let mut k = [0u32; I31_LEN];
    let mut t1 = [0u32; I31_LEN];
    let mut t2 = [0u32; I31_LEN];
    let mut tt = [0u8; ORDER_LEN << 1];
    let mut eu = [0u8; POINT_LEN];

    /*
     * If the curve is not supported, then exit with an error.
     */
    if ((impl_.supported_curves >> sk.curve) & 1) == 0 {
        return 0;
    }

    /*
     * Get the curve parameters (generator and order).
     */
    let cd = match sk.curve {
        BR_EC_secp256r1 => &br_secp256r1,
        BR_EC_secp384r1 => &br_secp384r1,
        BR_EC_secp521r1 => &br_secp521r1,
        _ => return 0,
    };

    /*
     * Get modulus.
     */
    let nlen = cd.order.len();
    br_i31_decode(&mut n, cd.order, nlen);
    let n0i = br_i31_ninv31(n[1]);

    /*
     * Get private key as an i31 integer. Also checks it is well-defined.
     */
    if br_i31_decode_mod(&mut x, sk.x, sk.x.len(), &n) == 0 {
        return 0;
    }
    if br_i31_iszero(&x) != 0 {
        return 0;
    }

    /*
     * Get hash length.
     */
    let hash_len = ((hf.desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK) as usize;

    /*
     * Truncate and reduce the hash value modulo the curve order.
     */
    br_ecdsa_i31_bits2int(&mut m, hash_value, hash_len, n[0]);
    {
        let sub = br_i31_sub(&mut m, &n, 0) ^ 1;
        br_i31_sub(&mut m, &n, sub);
    }

    /*
     * RFC 6979 generation of the "k" value, using HMAC_DRBG.
     */
    br_i31_encode(&mut tt[..nlen], nlen, &x);
    br_i31_encode(&mut tt[nlen..2 * nlen], nlen, &m);
    let mut drbg = br_hmac_drbg_context {
        vtable: &crate::rand::br_hmac_drbg_vtable,
        K: [0u8; 64],
        V: [0u8; 64],
        digest_class: hf,
    };
    br_hmac_drbg_init(&mut drbg, hf, &tt[..nlen << 1], nlen << 1);
    loop {
        br_hmac_drbg_generate(&mut drbg, &mut tt[..nlen], nlen);
        br_ecdsa_i31_bits2int(&mut k, &tt[..nlen], nlen, n[0]);
        if br_i31_iszero(&k) != 0 {
            continue;
        }
        if br_i31_sub(&mut k, &n, 0) != 0 {
            break;
        }
    }

    /*
     * Compute k*G and extract the X coordinate, then reduce modulo the order.
     */
    br_i31_encode(&mut tt[..nlen], nlen, &k);
    let ulen = (impl_.mulgen)(&mut eu, &tt[..nlen], sk.curve);
    br_i31_zero(&mut r, n[0]);
    br_i31_decode(&mut r, &eu[1..1 + (ulen >> 1)], ulen >> 1);
    r[0] = n[0];
    {
        let sub = br_i31_sub(&mut r, &n, 0) ^ 1;
        br_i31_sub(&mut r, &n, sub);
    }

    /*
     * Compute 1/k in double-Montgomery representation.
     */
    br_i31_from_monty(&mut k, &n, n0i);
    br_i31_from_monty(&mut k, &n, n0i);
    tt[..nlen].copy_from_slice(cd.order);
    tt[nlen - 1] = tt[nlen - 1].wrapping_sub(2);
    {
        let exp = tt; // copy so we can borrow t1/t2 mutably
        br_i31_modpow(&mut k, &exp[..nlen], nlen, &n, n0i, &mut t1, &mut t2);
    }

    /*
     * Compute s = (m+xr)/k (mod n).
     */
    br_i31_from_monty(&mut m, &n, n0i);
    br_i31_montymul(&mut t1, &x, &r, &n, n0i);
    let mut ctl = br_i31_add(&mut t1, &m, 1);
    ctl |= br_i31_sub(&mut t1, &n, 0) ^ 1;
    br_i31_sub(&mut t1, &n, ctl);
    br_i31_montymul(&mut s, &t1, &k, &n, n0i);

    /*
     * Encode r and s in the signature.
     */
    br_i31_encode(&mut sig[..nlen], nlen, &r);
    br_i31_encode(&mut sig[nlen..2 * nlen], nlen, &s);
    nlen << 1
}
