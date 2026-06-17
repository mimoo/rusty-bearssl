/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_pkcs1_vrfy` (mirrors `src/rsa/rsa_i31_pkcs1_vrfy.c`).

use super::{br_rsa_i31_public, br_rsa_pkcs1_sig_unpad, br_rsa_public_key, BR_MAX_RSA_SIZE};

/// see bearssl_rsa.h
pub fn br_rsa_i31_pkcs1_vrfy(
    x: &[u8],
    hash_oid: Option<&[u8]>,
    hash_len: usize,
    pk: &br_rsa_public_key,
    hash_out: &mut [u8],
) -> u32 {
    let mut sig = [0u8; BR_MAX_RSA_SIZE >> 3];
    let xlen = x.len();

    if xlen > sig.len() {
        return 0;
    }
    sig[..xlen].copy_from_slice(x);
    if br_rsa_i31_public(&mut sig[..xlen], pk) == 0 {
        return 0;
    }
    br_rsa_pkcs1_sig_unpad(&sig[..xlen], hash_oid, hash_len, hash_out)
}
