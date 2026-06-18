/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS client context and configuration (`ssl_client.c`, `ssl_client_full.c`
//! and the `ssl_engine_default_*` profile setters).
//!
//! Only the cipher suites whose record layers are implemented in this port
//! (AES-GCM and ChaCha20+Poly1305, with ECDHE-RSA/ECDSA and RSA key exchange)
//! are wired up; CBC/CCM/3DES suites are accepted in the suite list but their
//! key-switch opcodes fail the handshake if selected.

use crate::ec::{br_ec_get_default, br_ecdsa_i31_vrfy_asn1};
use crate::hash::{
    br_md5_vtable, br_sha1_vtable, br_sha224_vtable, br_sha256_vtable, br_sha384_vtable,
    br_sha512_vtable, br_ghash_ctmul, br_md5_ID, br_sha512_ID,
};
use crate::rsa::br_rsa_pkcs1_vrfy_get_default;
use crate::ssl::{br_tls10_prf, br_tls12_sha256_prf, br_tls12_sha384_prf, br_tls_prf_impl};
use crate::symcipher::{br_aes_ct_ctr_vtable, br_chacha20_ct_run, br_poly1305_ctmul_run};
use crate::x509::{br_x509_minimal_init, br_x509_trust_anchor, X509Engine};

use super::ssl_engine::*;

/// TLS cipher suite identifiers used by the "full" client profile that this
/// port can negotiate (ECDHE/ECDH/RSA key exchange with GCM or ChaCha20).
pub mod suites {
    pub const ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
    pub const ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;
    pub const ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
    pub const ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
    pub const ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;
    pub const ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;
    pub const ECDH_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02D;
    pub const ECDH_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC031;
    pub const RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009C;
    pub const RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009D;
}

/// The default suite list for a client supporting the implemented record
/// layers (subset of the upstream "full" list).
pub const SUITES_SUPPORTED: [u16; 10] = [
    suites::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    suites::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    suites::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    suites::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    suites::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    suites::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    suites::ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    suites::ECDH_RSA_WITH_AES_128_GCM_SHA256,
    suites::RSA_WITH_AES_128_GCM_SHA256,
    suites::RSA_WITH_AES_256_GCM_SHA384,
];

/// Default X.509 validation date used by [`br_ssl_client_context::init_full`]
/// (days since 0000-01-01, proleptic Gregorian; ~2021, inside the BearSSL
/// sample certificates' validity window).
pub const DEFAULT_VALID_DAYS: u32 = 737956;

/// TLS client context (`br_ssl_client_context`). Wraps the engine.
pub struct br_ssl_client_context {
    pub eng: br_ssl_engine_context,
}

impl br_ssl_engine_context {
    /// see bearssl_ssl.h (`br_ssl_engine_set_versions`)
    pub fn set_versions(&mut self, version_min: u16, version_max: u16) {
        self.set16(OFF_VERSION_MIN, version_min);
        self.set16(OFF_VERSION_MAX, version_max);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_hash`)
    pub fn set_hash(&mut self, id: i32, hc: Option<&'static crate::hash::br_hash_class>) {
        crate::hash::br_multihash_setimpl(&mut self.mhash, id, hc);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_x509`)
    pub fn set_x509(&mut self, x509: Box<dyn X509Engine + 'static>) {
        self.x509 = Some(x509);
    }

    /// Set the PRF implementations (TLS 1.0/1.1 and TLS 1.2 SHA-256/384).
    pub fn set_prf10(&mut self, prf: br_tls_prf_impl) {
        self.prf10 = Some(prf);
    }
    pub fn set_prf_sha256(&mut self, prf: br_tls_prf_impl) {
        self.prf_sha256 = Some(prf);
    }
    pub fn set_prf_sha384(&mut self, prf: br_tls_prf_impl) {
        self.prf_sha384 = Some(prf);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_aes_gcm`)
    pub fn set_default_aes_gcm(&mut self) {
        self.has_gcm = true;
        self.iaes_ctr = Some(&br_aes_ct_ctr_vtable);
        self.ighash = Some(br_ghash_ctmul);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_chapol`)
    pub fn set_default_chapol(&mut self) {
        self.has_chapol = true;
        self.ichacha = Some(br_chacha20_ct_run);
        self.ipoly = Some(br_poly1305_ctmul_run);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_ec`)
    pub fn set_default_ec(&mut self) {
        self.iec = Some(br_ec_get_default());
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_ecdsa`)
    pub fn set_default_ecdsa(&mut self) {
        self.iec = Some(br_ec_get_default());
        self.iecdsa = Some(br_ecdsa_i31_vrfy_asn1);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_rsavrfy`)
    pub fn set_default_rsavrfy(&mut self) {
        self.irsavrfy = Some(br_rsa_pkcs1_vrfy_get_default());
    }
}

impl br_ssl_client_context {
    /// see bearssl_ssl.h (`br_ssl_client_zero`)
    pub fn zero() -> Self {
        br_ssl_client_context {
            eng: br_ssl_engine_context::new(),
        }
    }

    /// see bearssl_ssl.h (`br_ssl_client_init_full`)
    ///
    /// Builds a client supporting the implemented suites. The X.509 minimal
    /// engine is constructed internally over the provided `'static` trust
    /// anchors and linked into the engine.
    pub fn init_full(trust_anchors: &'static [br_x509_trust_anchor<'static>]) -> Self {
        let mut cc = Self::zero();
        cc.eng.set_versions(BR_TLS10, BR_TLS12);

        // X.509 minimal engine (uses SHA-256 to hash DNs).
        let mut xc = br_x509_minimal_init(&br_sha256_vtable, trust_anchors);
        xc.set_rsa(br_rsa_pkcs1_vrfy_get_default());
        xc.set_ecdsa(br_ec_get_default(), br_ecdsa_i31_vrfy_asn1);
        // Validation time: upstream `br_ssl_client_init_full` leaves the X.509
        // engine to use the OS clock. We have no portable clock dependency, so
        // set a fixed sane time. Callers needing real time should build the
        // X.509 engine themselves and pass it via `init_full_x509`.
        xc.set_time(DEFAULT_VALID_DAYS, 0);

        cc.eng.set_suites(&SUITES_SUPPORTED);
        cc.eng.set_default_rsavrfy();
        cc.eng.set_default_ecdsa();

        // Activate all hash functions in both engines.
        let hashes: [&'static crate::hash::br_hash_class; 6] = [
            &br_md5_vtable,
            &br_sha1_vtable,
            &br_sha224_vtable,
            &br_sha256_vtable,
            &br_sha384_vtable,
            &br_sha512_vtable,
        ];
        for id in (br_md5_ID as i32)..=(br_sha512_ID as i32) {
            let hc = hashes[(id - 1) as usize];
            cc.eng.set_hash(id, Some(hc));
            xc.set_hash(id, Some(hc));
        }

        cc.eng.set_x509(Box::new(xc));

        cc.eng.set_prf10(br_tls10_prf);
        cc.eng.set_prf_sha256(br_tls12_sha256_prf);
        cc.eng.set_prf_sha384(br_tls12_sha384_prf);

        cc.eng.set_default_aes_gcm();
        cc.eng.set_default_chapol();
        cc
    }

    /// see bearssl_ssl.h (`br_ssl_client_reset`)
    ///
    /// `server_name` is the SNI name; resets the engine and starts a new
    /// handshake. Returns true on success.
    pub fn reset(&mut self, server_name: Option<&str>, _resume_session: bool) -> bool {
        self.eng.set_buffer_default();
        let vmin = self.eng.get16(OFF_VERSION_MIN);
        self.eng.set16(OFF_VERSION_OUT, vmin);
        if !self.eng.init_rand() {
            return false;
        }
        self.eng.set8(OFF_RENEG, 0);

        // Store SNI server name into mem[OFF_SERVER_NAME] (NUL-terminated).
        match server_name {
            None => {
                self.eng.mem[OFF_SERVER_NAME] = 0;
            }
            Some(s) => {
                let bytes = s.as_bytes();
                if bytes.len() + 1 > 256 {
                    self.eng.fail(BR_ERR_BAD_PARAM);
                    return false;
                }
                self.eng.mem[OFF_SERVER_NAME..OFF_SERVER_NAME + bytes.len()]
                    .copy_from_slice(bytes);
                self.eng.mem[OFF_SERVER_NAME + bytes.len()] = 0;
            }
        }

        self.eng.hs_reset(HsKind::Client);
        self.eng.last_error() == BR_ERR_OK
    }
}
