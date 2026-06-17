/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS 1.0/1.1 PRF using MD5 + SHA-1 (`src/ssl/prf_md5sha1.c`).

use super::br_tls_prf_seed_chunk;
use super::prf::br_tls_phash;
use crate::hash::{br_md5_vtable, br_sha1_vtable};

/// see bearssl.h
pub fn br_tls10_prf(dst: &mut [u8], secret: &[u8], label: &[u8], seed: &[br_tls_prf_seed_chunk]) {
    let slen = (secret.len() + 1) >> 1;
    for b in dst.iter_mut() {
        *b = 0;
    }
    // First half of the secret keys the MD5 leg; the second half (overlapping
    // by one byte for odd lengths) keys the SHA-1 leg.
    br_tls_phash(dst, &br_md5_vtable, &secret[..slen], label, seed);
    br_tls_phash(dst, &br_sha1_vtable, &secret[secret.len() - slen..], label, seed);
}
