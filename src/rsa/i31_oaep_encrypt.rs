/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_oaep_encrypt` (mirrors `src/rsa/rsa_i31_oaep_encrypt.c`).

use super::{br_rsa_i31_public, br_rsa_oaep_pad, br_rsa_public_key};
use crate::hash::br_hash_class;
use crate::rand::PrngState;

/// see bearssl_rsa.h
pub fn br_rsa_i31_oaep_encrypt(
    rnd: &mut dyn PrngState,
    dig: &'static br_hash_class,
    label: &[u8],
    pk: &br_rsa_public_key,
    dst: &mut [u8],
    src: &[u8],
) -> usize {
    let dlen = br_rsa_oaep_pad(rnd, dig, label, pk, dst, src);
    if dlen == 0 {
        return 0;
    }
    let ok = br_rsa_i31_public(&mut dst[..dlen], pk);
    dlen & (ok as usize).wrapping_neg()
}
