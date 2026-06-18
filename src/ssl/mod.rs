/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS / SSL (`src/ssl/`).
//!
//! ## Implemented
//!
//! - TLS PRF family (`prf.c`, `prf_md5sha1.c`, `prf_sha256.c`, `prf_sha384.c`).
//! - Record layers: GCM (`ssl_rec_gcm.c`), ChaCha20-Poly1305
//!   (`ssl_rec_chapol.c`), CBC (`ssl_rec_cbc.c`, constant-time MAC-then-encrypt
//!   via `br_hmac_outCT`) and CCM (`ssl_rec_ccm.c`, 8- and 16-byte tags).
//! - Engine core + record state machine (`ssl_engine.c`) with the GCM / CBC /
//!   CCM / ChaCha20-Poly1305 key-switch functions.
//! - TLS 1.2 CLIENT: T0 handshake interpreter (`ssl_hs_client.c`) + full client
//!   config (`ssl_client.c`/`ssl_client_full.c`). Completes live handshakes
//!   against `brssl server` for ECDHE_RSA with GCM / CBC / ChaCha20-Poly1305.
//! - TLS 1.2 SERVER: T0 handshake interpreter (`ssl_hs_server.c`) + config
//!   (`ssl_server.c`, `ssl_server_full_rsa.c`, `ssl_server_full_ec.c`) and the
//!   single-certificate policies (`ssl_scert_single_rsa.c`,
//!   `ssl_scert_single_ec.c`). Completes live handshakes against `brssl client`
//!   for ECDHE_RSA (GCM / CBC / ChaCha20-Poly1305) and RSA key exchange.
//! - Blocking I/O wrapper (`ssl_io.c`, [`br_sslio_context`]).
//! - LRU session cache (`ssl_lru.c`, [`br_ssl_session_cache_lru`]).
//!
//! - Client-certificate authentication (mutual TLS): the signature-based
//!   single-RSA client-auth policy (`ssl_ccert_single_rsa.c`) plus the
//!   `do-client-sign` handshake path. The client presents its certificate and
//!   signs the CertificateVerify when the server sends a CertificateRequest
//!   (see [`br_ssl_client_context::set_single_rsa`]). Verified live against
//!   `brssl server -CA`.
//!
//! ## Deferred
//!
//! - Static-ECDH client authentication (`BR_AUTH_ECDH`, the `do_keyx` branch of
//!   `ssl_ccert_single_ec.c`): the [`ClientCertPolicy`] trait covers the
//!   signature path (`choose` + `do_sign`); the static-ECDH client-auth key
//!   exchange is not wired. The single-EC signature (ECDSA) policy
//!   (`ssl_ccert_single_ec.c` sign path) is structurally identical to the RSA
//!   one and can be added the same way.

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
mod ssl_lru;
mod ssl_server;
mod ssl_rec_cbc;
mod ssl_rec_ccm;
mod ssl_rec_chapol;
mod ssl_rec_gcm;

pub use ssl_client::{br_ssl_client_context, SUITES_SUPPORTED};
pub use ssl_engine::{
    br_ssl_choose_hash, br_ssl_engine_context, BR_ERR_BAD_HANDSHAKE, BR_ERR_BAD_MAC, BR_ERR_OK,
    BR_SSL_APPLICATION_DATA, BR_SSL_CLOSED, BR_SSL_RECVAPP, BR_SSL_RECVREC, BR_SSL_SENDAPP,
    BR_SSL_SENDREC, BR_TLS10, BR_TLS11, BR_TLS12,
};

pub use ssl_io::{br_sslio_context, LowRead, LowResult, LowWrite};
pub use ssl_engine::{
    ClientCertChoices, ClientCertPolicy, ServerChoices, ServerChooseCtx, ServerPolicy,
    SslSessionCache, BR_AUTH_ECDSA, BR_AUTH_RSA,
};
pub use ssl_lru::br_ssl_session_cache_lru;
pub use ssl_server::{
    br_ssl_server_context, RsaPrivateKeyParts, BR_KEYTYPE_EC, BR_KEYTYPE_RSA,
};
pub use ssl_rec_cbc::{
    br_sslrec_in_cbc_context, br_sslrec_in_cbc_init, br_sslrec_out_cbc_context,
    br_sslrec_out_cbc_init, cbc_check_length, cbc_decrypt, cbc_encrypt, cbc_max_plaintext,
};
pub use ssl_rec_ccm::{
    br_sslrec_ccm_context, br_sslrec_in_ccm_init, br_sslrec_out_ccm_init, ccm_check_length,
    ccm_decrypt, ccm_encrypt, ccm_max_plaintext,
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
