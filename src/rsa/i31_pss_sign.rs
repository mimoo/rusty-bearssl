/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_pss_sign` (mirrors `src/rsa/rsa_i31_pss_sign.c`).

use super::{br_rsa_i31_private, br_rsa_private_key, br_rsa_pss_sig_pad};
use crate::hash::br_hash_class;
use crate::rand::PrngState;

/// see bearssl_rsa.h
pub fn br_rsa_i31_pss_sign(
    rng: Option<&mut dyn PrngState>,
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    sk: &br_rsa_private_key,
    x: &mut [u8],
) -> u32 {
    if br_rsa_pss_sig_pad(rng, hf_data, hf_mgf1, hash, salt_len, sk.n_bitlen, x) == 0 {
        return 0;
    }
    br_rsa_i31_private(x, sk)
}
