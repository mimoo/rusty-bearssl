/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_public` (mirrors `src/rsa/rsa_i31_pub.c`).

use super::{br_rsa_public_key, BR_MAX_RSA_SIZE};
use crate::int::{
    br_i31_decode, br_i31_decode_mod, br_i31_encode, br_i31_modpow_opt, br_i31_ninv31,
};

/// As a strict minimum, we need four buffers that can hold a modular integer
/// (`TLEN`).
const TLEN: usize = 4 * (2 + ((BR_MAX_RSA_SIZE + 30) / 31));

/// see bearssl_rsa.h
///
/// RSA public-key operation: replace `x` with `x^e mod n`. The operand length
/// must equal the actual modulus length. Returns 1 on success, 0 on error.
pub fn br_rsa_i31_public(x: &mut [u8], pk: &br_rsa_public_key) -> u32 {
    let xlen = x.len();
    let mut tmp = [0u32; 1 + TLEN];

    // Get the actual length of the modulus and check it fits, and that the
    // length of x[] is valid.
    let mut noff = 0usize;
    let mut nlen = pk.n.len();
    while nlen > 0 && pk.n[noff] == 0 {
        noff += 1;
        nlen -= 1;
    }
    if nlen == 0 || nlen > (BR_MAX_RSA_SIZE >> 3) || xlen != nlen {
        return 0;
    }
    let n = &pk.n[noff..noff + nlen];

    let mut z = (nlen as isize) << 3;
    let mut fwlen = 1usize;
    while z > 0 {
        z -= 31;
        fwlen += 1;
    }
    // Round up length to an even number.
    fwlen += fwlen & 1;

    // m = tmp[0..]; a = tmp[fwlen..]; t = tmp[2*fwlen..].
    // Decode the modulus into m.
    br_i31_decode(&mut tmp[..], n, nlen);
    let m0i = br_i31_ninv31(tmp[1]);

    // Note: if m[] is even, then m0i == 0. Otherwise, m0i must be odd.
    let mut r = m0i & 1;

    // Decode x[] into a[]; also check its value is proper.
    {
        let (m, rest) = tmp.split_at_mut(fwlen);
        let a = &mut rest[..]; // a starts at offset fwlen
        r &= br_i31_decode_mod(a, x, xlen, m);
    }

    // Compute the modular exponentiation a = a^e mod m.
    {
        let (m, rest) = tmp.split_at_mut(fwlen);
        let (a, t) = rest.split_at_mut(fwlen);
        br_i31_modpow_opt(a, pk.e, pk.e.len(), m, m0i, t, TLEN - 2 * fwlen);
    }

    // Encode the result.
    let a = &tmp[fwlen..2 * fwlen];
    br_i31_encode(x, xlen, a);
    r
}
