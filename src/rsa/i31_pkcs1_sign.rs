/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_pkcs1_sign` (mirrors `src/rsa/rsa_i31_pkcs1_sign.c`).

use super::{br_rsa_i31_private, br_rsa_pkcs1_sig_pad, br_rsa_private_key};

/// see bearssl_rsa.h
pub fn br_rsa_i31_pkcs1_sign(
    hash_oid: Option<&[u8]>,
    hash: &[u8],
    hash_len: usize,
    sk: &br_rsa_private_key,
    x: &mut [u8],
) -> u32 {
    if br_rsa_pkcs1_sig_pad(hash_oid, hash, hash_len, sk.n_bitlen, x) == 0 {
        return 0;
    }
    br_rsa_i31_private(x, sk)
}
