/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS 1.2 PRF with SHA-384 (`src/ssl/prf_sha384.c`).

use super::br_tls_prf_seed_chunk;
use super::prf::br_tls_phash;
use crate::hash::br_sha384_vtable;

/// see bearssl.h
pub fn br_tls12_sha384_prf(dst: &mut [u8], secret: &[u8], label: &[u8], seed: &[br_tls_prf_seed_chunk]) {
    for b in dst.iter_mut() {
        *b = 0;
    }
    br_tls_phash(dst, &br_sha384_vtable, secret, label, seed);
}
