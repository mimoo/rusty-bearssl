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

mod client_codeblock;
mod prf;
mod prf_md5sha1;
mod prf_sha256;
mod prf_sha384;
mod server_codeblock;
mod ssl_client;
mod ssl_engine;
mod ssl_hs_client;
mod ssl_hs_server;
mod ssl_io;
mod ssl_rec_cbc;
mod ssl_rec_chapol;
mod ssl_rec_gcm;

pub use ssl_client::{br_ssl_client_context, SUITES_SUPPORTED};
pub use ssl_engine::{
    br_ssl_choose_hash, br_ssl_engine_context, BR_ERR_BAD_HANDSHAKE, BR_ERR_BAD_MAC, BR_ERR_OK,
    BR_SSL_APPLICATION_DATA, BR_SSL_CLOSED, BR_SSL_RECVAPP, BR_SSL_RECVREC, BR_SSL_SENDAPP,
    BR_SSL_SENDREC, BR_TLS10, BR_TLS11, BR_TLS12,
};

pub use ssl_io::{br_sslio_context, LowRead, LowResult, LowWrite};
pub use ssl_rec_cbc::{
    br_sslrec_in_cbc_context, br_sslrec_in_cbc_init, br_sslrec_out_cbc_context,
    br_sslrec_out_cbc_init, cbc_check_length, cbc_decrypt, cbc_encrypt, cbc_max_plaintext,
};

pub use prf::br_tls_phash;
pub use prf_md5sha1::br_tls10_prf;
pub use prf_sha256::br_tls12_sha256_prf;
pub use prf_sha384::br_tls12_sha384_prf;
pub use ssl_rec_chapol::{
    br_poly1305_run, br_sslrec_chapol_context, br_sslrec_in_chapol_init, br_sslrec_out_chapol_init,
    chapol_check_length, chapol_decrypt, chapol_encrypt, chapol_max_plaintext,
};
pub use ssl_rec_gcm::{
    br_sslrec_gcm_context, br_sslrec_in_gcm_init, br_sslrec_out_gcm_init, gcm_check_length,
    gcm_decrypt, gcm_encrypt, gcm_max_plaintext,
};
