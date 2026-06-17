/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_ssl_decrypt` (mirrors `src/rsa/rsa_ssl_decrypt.c`).

use super::{br_rsa_private, br_rsa_private_key};
use crate::inner::{EQ, NEQ};

/// see bearssl_rsa.h
///
/// RSA decryption helper for SSL/TLS: decrypt `data` with `core`, verify the
/// PKCS#1 v1.5 type-2 padding in constant-time, and copy the 48-byte pre-master
/// secret to the start of `data`. Returns 1 on success, 0 on error.
pub fn br_rsa_ssl_decrypt(
    core: br_rsa_private,
    sk: &br_rsa_private_key,
    data: &mut [u8],
    len: usize,
) -> u32 {
    // A first check on length (not constant-time; only depends on lengths).
    if len < 59 || len != ((sk.n_bitlen + 7) >> 3) as usize {
        return 0;
    }
    let mut x = core(data, sk);

    x &= EQ(data[0] as u32, 0x00);
    x &= EQ(data[1] as u32, 0x02);
    for u in 2..(len - 49) {
        x &= NEQ(data[u] as u32, 0);
    }
    x &= EQ(data[len - 49] as u32, 0x00);
    data.copy_within(len - 48..len, 0);
    x
}
