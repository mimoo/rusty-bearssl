/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_oaep_decrypt` (mirrors `src/rsa/rsa_i31_oaep_decrypt.c`).

use super::{br_rsa_i31_private, br_rsa_oaep_unpad, br_rsa_private_key};
use crate::hash::br_hash_class;

/// see bearssl_rsa.h
pub fn br_rsa_i31_oaep_decrypt(
    dig: &'static br_hash_class,
    label: &[u8],
    sk: &br_rsa_private_key,
    data: &mut [u8],
    len: &mut usize,
) -> u32 {
    if *len != ((sk.n_bitlen + 7) >> 3) as usize {
        return 0;
    }
    let mut r = br_rsa_i31_private(&mut data[..*len], sk);
    r &= br_rsa_oaep_unpad(dig, label, data, len);
    r
}
