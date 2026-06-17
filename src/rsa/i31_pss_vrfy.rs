/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_pss_vrfy` (mirrors `src/rsa/rsa_i31_pss_vrfy.c`).

use super::{br_rsa_i31_public, br_rsa_pss_sig_unpad, br_rsa_public_key, BR_MAX_RSA_SIZE};
use crate::hash::br_hash_class;

/// see bearssl_rsa.h
pub fn br_rsa_i31_pss_vrfy(
    x: &[u8],
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    pk: &br_rsa_public_key,
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
    br_rsa_pss_sig_unpad(hf_data, hf_mgf1, hash, salt_len, pk, &mut sig[..xlen])
}
