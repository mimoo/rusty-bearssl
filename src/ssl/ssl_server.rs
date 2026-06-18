/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! TLS server context + configuration (`ssl_server.c`, `ssl_server_full_rsa.c`,
//! `ssl_server_full_ec.c`, `ssl_scert_single_rsa.c`, `ssl_scert_single_ec.c`).
//!
//! Wires the engine to drive the server T0 handshake. Two "single-certificate"
//! policies are provided: RSA (RSA key-exchange and ECDHE_RSA signatures) and
//! EC (ECDHE_ECDSA signatures and static ECDH). Only the record layers
//! implemented in this port can actually be negotiated.

use crate::ec::{br_ec_get_default, br_ecdsa_i31_sign_asn1, br_ecdsa_sign};
use crate::hash::{
    br_md5_vtable, br_sha1_vtable, br_sha224_vtable, br_sha256_vtable, br_sha384_vtable,
    br_sha512_vtable, br_md5_ID, br_sha1_ID, br_sha512_ID,
};
use crate::rsa::{
    br_rsa_pkcs1_sign, br_rsa_pkcs1_sign_get_default, br_rsa_private, br_rsa_private_get_default,
    br_rsa_private_key, br_rsa_ssl_decrypt, BR_HASH_OID_SHA1, BR_HASH_OID_SHA224,
    BR_HASH_OID_SHA256, BR_HASH_OID_SHA384, BR_HASH_OID_SHA512,
};

use super::ssl_engine::*;
use crate::ssl::{br_tls10_prf, br_tls12_sha256_prf, br_tls12_sha384_prf};

// Key-type flags (`inc/bearssl_x509.h`).
pub const BR_KEYTYPE_RSA: u32 = 1;
pub const BR_KEYTYPE_EC: u32 = 2;
pub const BR_KEYTYPE_KEYX: u32 = 0x10;
pub const BR_KEYTYPE_SIGN: u32 = 0x20;

// Key-exchange selectors, extracted from the translated suite flags (`flags >>
// 12`, see `ssl_hs_common.t0`).
pub const BR_SSLKEYX_RSA: u16 = 0;
pub const BR_SSLKEYX_ECDHE_RSA: u16 = 1;
pub const BR_SSLKEYX_ECDHE_ECDSA: u16 = 2;
pub const BR_SSLKEYX_ECDH_RSA: u16 = 3;
pub const BR_SSLKEYX_ECDH_ECDSA: u16 = 4;

/// The default server suite list (same record layers as the client).
pub const SERVER_SUITES: [u16; 19] = crate::ssl::SUITES_SUPPORTED;

/// TLS server context (`br_ssl_server_context`). Wraps the engine.
pub struct br_ssl_server_context {
    pub eng: br_ssl_engine_context,
}

// ---- owned single-certificate policies --------------------------------------

/// Owned RSA private key material (the `br_rsa_private_key` borrows slices, so
/// we keep the bytes alive here and rebuild the borrowing struct on demand).
struct OwnedRsaKey {
    n_bitlen: u32,
    p: Vec<u8>,
    q: Vec<u8>,
    dp: Vec<u8>,
    dq: Vec<u8>,
    iq: Vec<u8>,
}

impl OwnedRsaKey {
    fn as_key(&self) -> br_rsa_private_key<'_> {
        br_rsa_private_key {
            n_bitlen: self.n_bitlen,
            p: &self.p,
            q: &self.q,
            dp: &self.dp,
            dq: &self.dq,
            iq: &self.iq,
        }
    }
}

const HASH_OID: [&[u8]; 5] = [
    BR_HASH_OID_SHA1,
    BR_HASH_OID_SHA224,
    BR_HASH_OID_SHA256,
    BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
];

/// Single-RSA-certificate policy (`br_ssl_server_policy_rsa_context`): supports
/// the RSA key-exchange and ECDHE_RSA (RSA-signed) cipher suites.
struct SingleRsaPolicy {
    chain: Vec<Vec<u8>>,
    sk: OwnedRsaKey,
    allowed_usages: u32,
    irsacore: br_rsa_private,
    irsasign: br_rsa_pkcs1_sign,
}

impl ServerPolicy for SingleRsaPolicy {
    fn choose(&self, ctx: &ServerChooseCtx) -> Option<ServerChoices> {
        let (hash_id, fh) = if ctx.version < BR_TLS12 {
            (0i32, true)
        } else {
            let h = br_ssl_choose_hash(ctx.hashes);
            (h, h != 0)
        };
        for &(id, flags) in ctx.client_suites {
            match flags >> 12 {
                BR_SSLKEYX_RSA => {
                    if (self.allowed_usages & BR_KEYTYPE_KEYX) != 0 {
                        return Some(ServerChoices {
                            cipher_suite: id,
                            algo_id: 0,
                            chain: self.chain.clone(),
                        });
                    }
                }
                BR_SSLKEYX_ECDHE_RSA => {
                    if (self.allowed_usages & BR_KEYTYPE_SIGN) != 0 && fh {
                        return Some(ServerChoices {
                            cipher_suite: id,
                            algo_id: hash_id as u32 + 0xFF00,
                            chain: self.chain.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn do_keyx(&self, data: &mut [u8], len: &mut usize) -> u32 {
        let key = self.sk.as_key();
        br_rsa_ssl_decrypt(self.irsacore, &key, data, *len)
    }

    fn do_sign(&self, algo_id: u32, data: &mut [u8], hv_len: usize, len: usize) -> usize {
        let mut hv = [0u8; 64];
        hv[..hv_len].copy_from_slice(&data[..hv_len]);
        let algo = algo_id & 0xFF;
        let hash_oid: Option<&[u8]> = if algo == 0 {
            None
        } else if (2..=6).contains(&algo) {
            Some(HASH_OID[(algo - 2) as usize])
        } else {
            return 0;
        };
        let key = self.sk.as_key();
        let sig_len = ((self.sk.n_bitlen + 7) >> 3) as usize;
        if len < sig_len {
            return 0;
        }
        if (self.irsasign)(hash_oid, &hv[..hv_len], hv_len, &key, &mut data[..sig_len]) == 1 {
            sig_len
        } else {
            0
        }
    }
}

/// Single-EC-certificate policy (`br_ssl_server_policy_ec_context`): supports
/// the ECDHE_ECDSA (ECDSA-signed) and static-ECDH cipher suites.
struct SingleEcPolicy {
    chain: Vec<Vec<u8>>,
    curve: i32,
    sk: Vec<u8>,
    allowed_usages: u32,
    cert_issuer_key_type: u32,
    isign: br_ecdsa_sign,
}

impl ServerPolicy for SingleEcPolicy {
    fn choose(&self, ctx: &ServerChooseCtx) -> Option<ServerChoices> {
        // ECDHE_ECDSA uses the signature-hash byte (`hashes >> 8`); pre-1.2
        // falls back to SHA-1.
        let hash_id = if ctx.version < BR_TLS12 {
            br_sha1_ID as i32
        } else {
            br_ssl_choose_hash(ctx.hashes >> 8)
        };
        for &(id, flags) in ctx.client_suites {
            match flags >> 12 {
                BR_SSLKEYX_ECDHE_ECDSA => {
                    if (self.allowed_usages & BR_KEYTYPE_SIGN) != 0 && hash_id != 0 {
                        return Some(ServerChoices {
                            cipher_suite: id,
                            algo_id: hash_id as u32 + 0xFF00,
                            chain: self.chain.clone(),
                        });
                    }
                }
                BR_SSLKEYX_ECDH_RSA | BR_SSLKEYX_ECDH_ECDSA => {
                    let want = if (flags >> 12) == BR_SSLKEYX_ECDH_RSA {
                        BR_KEYTYPE_RSA
                    } else {
                        BR_KEYTYPE_EC
                    };
                    if (self.allowed_usages & BR_KEYTYPE_KEYX) != 0
                        && self.cert_issuer_key_type == want
                    {
                        return Some(ServerChoices {
                            cipher_suite: id,
                            algo_id: 0,
                            chain: self.chain.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn do_keyx(&self, data: &mut [u8], len: &mut usize) -> u32 {
        // Static ECDH: multiply the client point by our private key, then keep
        // only the X coordinate (`se_do_keyx`).
        let iec = br_ec_get_default();
        let r = (iec.mul)(&mut data[..*len], &self.sk, self.curve);
        let mut xlen = 0usize;
        let xoff = (iec.xoff)(self.curve, &mut xlen);
        data.copy_within(xoff..xoff + xlen, 0);
        *len = xlen;
        r
    }

    fn do_sign(&self, algo_id: u32, data: &mut [u8], hv_len: usize, len: usize) -> usize {
        // ECDSA over the prepared hash value (`se_do_sign`). The hash class is
        // selected from the low byte of algo_id; all hashes are present in the
        // full profile.
        let iec = br_ec_get_default();
        let hc = match hash_class_by_id((algo_id & 0xFF) as i32) {
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
        (self.isign)(iec, hc, &hv[..hv_len], &sk, &mut data[..len])
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

impl br_ssl_engine_context {
    /// Install a server policy (`br_ssl_server_set_policy`-equivalent).
    fn set_policy(&mut self, policy: Box<dyn ServerPolicy>) {
        self.policy = Some(policy);
    }
}

impl br_ssl_server_context {
    /// see bearssl_ssl.h (`br_ssl_server_zero`)
    pub fn zero() -> Self {
        br_ssl_server_context {
            eng: br_ssl_engine_context::new(),
        }
    }

    /// Activate every supported hash function in the engine (used by the full
    /// profiles) and set the PRF + record-layer defaults.
    fn set_common_defaults(&mut self) {
        let hashes: [&'static crate::hash::br_hash_class; 6] = [
            &br_md5_vtable,
            &br_sha1_vtable,
            &br_sha224_vtable,
            &br_sha256_vtable,
            &br_sha384_vtable,
            &br_sha512_vtable,
        ];
        for id in (br_md5_ID as i32)..=(br_sha512_ID as i32) {
            self.eng.set_hash(id, Some(hashes[(id - 1) as usize]));
        }
        self.eng.set_prf10(br_tls10_prf);
        self.eng.set_prf_sha256(br_tls12_sha256_prf);
        self.eng.set_prf_sha384(br_tls12_sha384_prf);
        self.eng.set_default_aes_gcm();
        self.eng.set_default_aes_ccm();
        self.eng.set_default_aes_cbc();
        self.eng.set_default_des_cbc();
        self.eng.set_default_chapol();
        self.eng.set_default_ec();
    }

    /// see bearssl_ssl.h (`br_ssl_server_init_full_rsa`).
    ///
    /// `chain` is the server certificate chain (DER). `sk` provides the RSA
    /// private key components. The server will offer RSA-keyx and ECDHE_RSA
    /// suites.
    pub fn init_full_rsa(chain: Vec<Vec<u8>>, sk: RsaPrivateKeyParts) -> Self {
        let mut cc = Self::zero();
        cc.eng.set_versions(BR_TLS10, BR_TLS12);
        cc.eng.set_suites(&SERVER_SUITES);
        cc.eng.set_default_rsavrfy();
        cc.eng.set_default_ecdsa();
        cc.set_common_defaults();
        let policy = SingleRsaPolicy {
            chain,
            sk: OwnedRsaKey {
                n_bitlen: sk.n_bitlen,
                p: sk.p,
                q: sk.q,
                dp: sk.dp,
                dq: sk.dq,
                iq: sk.iq,
            },
            allowed_usages: BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
            irsacore: br_rsa_private_get_default(),
            irsasign: br_rsa_pkcs1_sign_get_default(),
        };
        cc.eng.set_policy(Box::new(policy));
        cc
    }

    /// see bearssl_ssl.h (`br_ssl_server_init_full_ec`).
    ///
    /// `cert_issuer_key_type` is the key type of the certificate's issuer
    /// (BR_KEYTYPE_RSA or BR_KEYTYPE_EC); it selects which static-ECDH suites
    /// are acceptable. `curve`/`sk` are the EC private key.
    pub fn init_full_ec(
        chain: Vec<Vec<u8>>,
        cert_issuer_key_type: u32,
        curve: i32,
        sk: Vec<u8>,
    ) -> Self {
        let mut cc = Self::zero();
        cc.eng.set_versions(BR_TLS10, BR_TLS12);
        cc.eng.set_suites(&SERVER_SUITES);
        cc.eng.set_default_rsavrfy();
        cc.eng.set_default_ecdsa();
        cc.set_common_defaults();
        let policy = SingleEcPolicy {
            chain,
            curve,
            sk,
            allowed_usages: BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
            cert_issuer_key_type,
            isign: br_ecdsa_i31_sign_asn1,
        };
        cc.eng.set_policy(Box::new(policy));
        cc
    }

    /// see bearssl_ssl.h (`br_ssl_server_reset`).
    pub fn reset(&mut self) -> bool {
        self.eng.set_buffer_default();
        if !self.eng.init_rand() {
            return false;
        }
        self.eng.set8(OFF_RENEG, 0);
        self.eng.hs_reset(HsKind::Server);
        self.eng.last_error() == BR_ERR_OK
    }
}

/// Owned RSA private-key parameters for [`br_ssl_server_context::init_full_rsa`].
pub struct RsaPrivateKeyParts {
    pub n_bitlen: u32,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub iq: Vec<u8>,
}

