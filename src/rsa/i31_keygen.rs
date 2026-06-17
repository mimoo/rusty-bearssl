/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_keygen` (mirrors `src/rsa/rsa_i31_keygen.c`).

use super::i31_keygen_inner::{br_rsa_i31_keygen_inner, KeygenOut};
use super::br_rsa_private_key;
use crate::int::br_i31_modpow_opt;
use crate::rand::PrngState;

/// see bearssl_rsa.h
///
/// Generate an RSA key pair of `size` bits. The private-key elements are written
/// into `kbuf_priv` and referenced by `sk`. If `out_pub` is `Some`, the public
/// key elements are written into its buffer and a [`br_rsa_public_key`] (built
/// from that buffer) plus its used length is returned in the [`KeygenOut`].
///
/// [`br_rsa_public_key`]: super::br_rsa_public_key
pub fn br_rsa_i31_keygen<'a>(
    rng: &mut dyn PrngState,
    sk: &mut br_rsa_private_key<'a>,
    kbuf_priv: &'a mut [u8],
    out_pub: Option<&'a mut [u8]>,
    size: usize,
    pubexp: u32,
) -> (u32, Option<KeygenOut>) {
    br_rsa_i31_keygen_inner(
        rng,
        sk,
        kbuf_priv,
        out_pub,
        size,
        pubexp,
        br_i31_modpow_opt,
    )
}
