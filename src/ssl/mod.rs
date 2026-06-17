/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS / SSL (`src/ssl/`).
//!
//! This module is being ported incrementally. Currently implemented: the TLS
//! PRF family (`prf.c`, `prf_md5sha1.c`, `prf_sha256.c`, `prf_sha384.c`). The
//! record layer, engine, handshake (T0-generated), client and server are
//! pending.

/// A seed chunk for the TLS PRF (`br_tls_prf_seed_chunk`). The label and seed
/// are concatenated as the PRF input; chunks may be empty.
#[derive(Clone, Copy)]
pub struct br_tls_prf_seed_chunk<'a> {
    pub data: &'a [u8],
}

/// A PRF implementation (`br_tls_prf_impl`): writes `dst.len()` derived bytes
/// from `secret`, `label` and the `seed` chunks.
pub type br_tls_prf_impl = fn(dst: &mut [u8], secret: &[u8], label: &[u8], seed: &[br_tls_prf_seed_chunk]);

mod prf;
mod prf_md5sha1;
mod prf_sha256;
mod prf_sha384;

pub use prf::br_tls_phash;
pub use prf_md5sha1::br_tls10_prf;
pub use prf_sha256::br_tls12_sha256_prf;
pub use prf_sha384::br_tls12_sha384_prf;
