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

use crate::ec::{br_ec_get_default, br_ecdsa_i31_sign_asn1, br_ecdsa_i31_vrfy_asn1};
use crate::hash::{
    br_md5_vtable, br_sha1_vtable, br_sha224_vtable, br_sha256_vtable, br_sha384_vtable,
    br_sha512_vtable, br_ghash_ctmul, br_md5_ID, br_sha512_ID,
};
use crate::rsa::{
    br_rsa_pkcs1_sign, br_rsa_pkcs1_sign_get_default, br_rsa_pkcs1_vrfy_get_default,
    br_rsa_private_key, BR_HASH_OID_SHA1, BR_HASH_OID_SHA224, BR_HASH_OID_SHA256,
    BR_HASH_OID_SHA384, BR_HASH_OID_SHA512,
};
use crate::ssl::{
    br_tls10_prf, br_tls12_sha256_prf, br_tls12_sha384_prf, br_tls_prf_impl, BR_AUTH_ECDSA,
    BR_AUTH_RSA,
};
use crate::symcipher::{
    br_aes_ct_cbcdec_vtable, br_aes_ct_cbcenc_vtable, br_aes_ct_ctr_vtable, br_aes_ct_ctrcbc_vtable,
    br_chacha20_ct_run, br_des_ct_cbcdec_vtable, br_des_ct_cbcenc_vtable, br_poly1305_ctmul_run,
};
use crate::x509::{br_x509_minimal_init_full, br_x509_trust_anchor, X509Engine};

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
    // CBC suites (HMAC-then-encrypt).
    pub const ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xC027;
    pub const ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xC013;
    pub const ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xC023;
    pub const ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xC009;
    pub const RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;
    pub const RSA_WITH_AES_128_CBC_SHA: u16 = 0x002F;
    pub const RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
    // CCM suites.
    pub const ECDHE_ECDSA_WITH_AES_128_CCM: u16 = 0xC0AC;
    pub const ECDHE_ECDSA_WITH_AES_128_CCM_8: u16 = 0xC0AE;
}

/// The default suite list for a client supporting the implemented record
/// layers (GCM, ChaCha20-Poly1305, CBC and CCM).
pub const SUITES_SUPPORTED: [u16; 19] = [
    suites::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    suites::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    suites::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    suites::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    suites::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    suites::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    suites::ECDHE_ECDSA_WITH_AES_128_CCM,
    suites::ECDHE_ECDSA_WITH_AES_128_CCM_8,
    suites::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    suites::ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    suites::ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    suites::ECDHE_RSA_WITH_AES_128_CBC_SHA,
    suites::ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    suites::ECDH_RSA_WITH_AES_128_GCM_SHA256,
    suites::RSA_WITH_AES_128_GCM_SHA256,
    suites::RSA_WITH_AES_256_GCM_SHA384,
    suites::RSA_WITH_AES_128_CBC_SHA256,
    suites::RSA_WITH_AES_128_CBC_SHA,
    suites::RSA_WITH_AES_256_CBC_SHA,
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

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_aes_cbc`)
    pub fn set_default_aes_cbc(&mut self) {
        self.iaes_cbcenc = Some(&br_aes_ct_cbcenc_vtable);
        self.iaes_cbcdec = Some(&br_aes_ct_cbcdec_vtable);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_aes_ccm`)
    pub fn set_default_aes_ccm(&mut self) {
        self.iaes_ctrcbc = Some(&br_aes_ct_ctrcbc_vtable);
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_default_des_cbc`)
    pub fn set_default_des_cbc(&mut self) {
        self.ides_cbcenc = Some(&br_des_ct_cbcenc_vtable);
        self.ides_cbcdec = Some(&br_des_ct_cbcdec_vtable);
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

        // X.509 minimal engine: SHA-256 DN hashing, i31 RSA+ECDSA verifiers and
        // all six hashes (`br_x509_minimal_init_full`).
        let mut xc = br_x509_minimal_init_full(trust_anchors);
        // Validation time: upstream `br_ssl_client_init_full` leaves the X.509
        // engine to use the OS clock. We have no portable clock dependency, so
        // set a fixed sane time. Callers needing real time should build the
        // X.509 engine themselves and pass it via `init_full_x509`.
        xc.set_time(DEFAULT_VALID_DAYS, 0);

        cc.eng.set_suites(&SUITES_SUPPORTED);
        cc.eng.set_default_rsavrfy();
        cc.eng.set_default_ecdsa();

        // Activate all hash functions in the engine (the multi-hasher used for
        // the handshake transcript + PRF seeds).
        let hashes: [&'static crate::hash::br_hash_class; 6] = [
            &br_md5_vtable,
            &br_sha1_vtable,
            &br_sha224_vtable,
            &br_sha256_vtable,
            &br_sha384_vtable,
            &br_sha512_vtable,
        ];
        for id in (br_md5_ID as i32)..=(br_sha512_ID as i32) {
            cc.eng.set_hash(id, Some(hashes[(id - 1) as usize]));
        }

        cc.eng.set_x509(Box::new(xc));

        cc.eng.set_prf10(br_tls10_prf);
        cc.eng.set_prf_sha256(br_tls12_sha256_prf);
        cc.eng.set_prf_sha384(br_tls12_sha384_prf);

        cc.eng.set_default_aes_gcm();
        cc.eng.set_default_aes_ccm();
        cc.eng.set_default_aes_cbc();
        cc.eng.set_default_des_cbc();
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

    /// see bearssl_ssl.h (`br_ssl_client_set_single_rsa`).
    ///
    /// Install a single-certificate RSA client-auth handler: when the server
    /// sends a CertificateRequest, the client presents `chain` and signs the
    /// CertificateVerify with the RSA private key `sk`.
    pub fn set_single_rsa(&mut self, chain: Vec<Vec<u8>>, sk: RsaPrivateKeyParts) {
        let policy = SingleRsaClientCert {
            chain,
            sk,
            irsasign: br_rsa_pkcs1_sign_get_default(),
        };
        self.eng.client_auth = Some(Box::new(policy));
    }

    /// see bearssl_ssl.h (`br_ssl_client_set_single_ec`).
    ///
    /// Install a single-certificate EC client-auth handler for the
    /// signature-based (ECDHE_ECDSA) case: the client presents `chain` and signs
    /// the CertificateVerify with the EC private key (`curve`, `sk` scalar).
    /// `allowed_usages` should include `BR_KEYTYPE_SIGN`. The static-ECDH client
    /// auth case (`BR_AUTH_ECDH`) is not handled (documented in `mod.rs`).
    pub fn set_single_ec(
        &mut self,
        chain: Vec<Vec<u8>>,
        curve: i32,
        sk: Vec<u8>,
        allowed_usages: u32,
    ) {
        let policy = SingleEcClientCert {
            chain,
            curve,
            sk,
            allowed_usages,
            isign: br_ecdsa_i31_sign_asn1,
        };
        self.eng.client_auth = Some(Box::new(policy));
    }
}

/// Owned RSA private-key parameters for [`br_ssl_client_context::set_single_rsa`].
pub use super::ssl_server::RsaPrivateKeyParts;

const CLIENT_HASH_OID: [&[u8]; 5] = [
    BR_HASH_OID_SHA1,
    BR_HASH_OID_SHA224,
    BR_HASH_OID_SHA256,
    BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
];

/// Single-RSA-certificate client-auth policy
/// (`br_ssl_client_certificate_rsa_context`).
struct SingleRsaClientCert {
    chain: Vec<Vec<u8>>,
    sk: RsaPrivateKeyParts,
    irsasign: br_rsa_pkcs1_sign,
}

impl ClientCertPolicy for SingleRsaClientCert {
    fn choose(&self, auth_types: u32) -> ClientCertChoices {
        // `cc_choose`: pick a hash for the RSA signature. If none of the
        // advertised (hash,RSA) pairs are usable and raw RSA (bit 0) is not
        // offered either, the caller gets auth_type 0 (no certificate).
        let x = br_ssl_choose_hash(auth_types);
        let usable = !(x == 0 && (auth_types & 1) == 0);
        ClientCertChoices {
            auth_type: if usable { BR_AUTH_RSA } else { 0 },
            hash_id: x,
            chain: if usable { self.chain.clone() } else { Vec::new() },
        }
    }

    fn do_sign(&self, hash_id: i32, hv_len: usize, data: &mut [u8], len: usize) -> usize {
        let mut hv = [0u8; 64];
        hv[..hv_len].copy_from_slice(&data[..hv_len]);
        let hash_oid: Option<&[u8]> = if hash_id == 0 {
            None
        } else if (2..=6).contains(&hash_id) {
            Some(CLIENT_HASH_OID[(hash_id - 2) as usize])
        } else {
            return 0;
        };
        let sig_len = ((self.sk.n_bitlen + 7) >> 3) as usize;
        if len < sig_len {
            return 0;
        }
        let key = br_rsa_private_key {
            n_bitlen: self.sk.n_bitlen,
            p: &self.sk.p,
            q: &self.sk.q,
            dp: &self.sk.dp,
            dq: &self.sk.dq,
            iq: &self.sk.iq,
        };
        if (self.irsasign)(hash_oid, &hv[..hv_len], hv_len, &key, &mut data[..sig_len]) == 1 {
            sig_len
        } else {
            0
        }
    }
}

/// Single-EC-certificate client-auth policy
/// (`br_ssl_client_certificate_ec_context`), signature (ECDSA) path.
struct SingleEcClientCert {
    chain: Vec<Vec<u8>>,
    curve: i32,
    sk: Vec<u8>,
    allowed_usages: u32,
    isign: crate::ec::br_ecdsa_sign,
}

impl ClientCertPolicy for SingleEcClientCert {
    fn choose(&self, auth_types: u32) -> ClientCertChoices {
        // `cc_choose` (signature branch): pick a hash for the ECDSA signature
        // from the signature-hash byte (`auth_types >> 8`). The static-ECDH
        // (BR_AUTH_ECDH) branch is not implemented here.
        let x = br_ssl_choose_hash(auth_types >> 8);
        let usable = x != 0 && (self.allowed_usages & super::ssl_server::BR_KEYTYPE_SIGN) != 0;
        ClientCertChoices {
            auth_type: if usable { BR_AUTH_ECDSA } else { 0 },
            hash_id: x,
            chain: if usable { self.chain.clone() } else { Vec::new() },
        }
    }

    fn do_sign(&self, hash_id: i32, hv_len: usize, data: &mut [u8], len: usize) -> usize {
        // `cc_do_sign`: ECDSA over the prepared hash value.
        let hc = match hash_class_by_id(hash_id) {
            Some(h) => h,
            None => return 0,
        };
        let mut hv = [0u8; 64];
        hv[..hv_len].copy_from_slice(&data[..hv_len]);
        if len < 139 {
            return 0;
        }
        let sk = crate::ec::br_ec_private_key {
            curve: self.curve,
            x: &self.sk,
        };
        (self.isign)(br_ec_get_default(), hc, &hv[..hv_len], &sk, &mut data[..len])
    }
}

/// Resolve a hash vtable by its BearSSL hash id (1=MD5 .. 6=SHA-512).
fn hash_class_by_id(id: i32) -> Option<&'static crate::hash::br_hash_class> {
    match id {
        x if x == br_md5_ID as i32 => Some(&br_md5_vtable),
        2 => Some(&br_sha1_vtable),
        3 => Some(&br_sha224_vtable),
        4 => Some(&br_sha256_vtable),
        5 => Some(&br_sha384_vtable),
        x if x == br_sha512_ID as i32 => Some(&br_sha512_vtable),
        _ => None,
    }
}
