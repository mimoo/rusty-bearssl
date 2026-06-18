/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `x509_minimal.c`.)
 */

//! The "minimal" X.509 path-validation engine (`src/x509/x509_minimal.c`).
//!
//! Performs a rudimentary but serviceable X.509 chain validation: subject/issuer
//! DN matching (by hash), certificate signature verification against the
//! previous certificate's key (and finally against a CA trust anchor), validity
//! date checks, Basic Constraints / Key Usage enforcement, direct trust of the
//! EE key against non-CA anchors, and Subject Alt Name / Common Name matching of
//! an expected server name.
//!
//! The T0 interpreter and code/data blocks are ported faithfully from the
//! generated C, using the genuine upstream `offsetof` values (baked into the
//! code block) and a flat `mem[]` buffer for byte-addressed fields. The
//! structured state that the T0 code reaches through native C helpers (the TBS
//! multi-hasher, the DN hasher, trust anchors, name elements, the signature
//! verifiers, the time callback) is held in ordinary Rust fields and accessed
//! from the custom opcodes, exactly as the C code calls its helper functions.

use crate::ec::{br_ec_impl, br_ec_public_key, br_ecdsa_vrfy};
use crate::hash::{
    br_hash_class, br_multihash_context, br_multihash_init, br_multihash_out,
    br_multihash_setimpl, br_multihash_update, BR_HASHDESC_OUT_MASK, BR_HASHDESC_OUT_OFF,
};
use crate::rsa::{br_rsa_pkcs1_vrfy, br_rsa_public_key};
use crate::x509::{br_x509_pkey, br_x509_trust_anchor, br_name_element, X509Engine};
use crate::x509::t0::*;

// ---- addressable context layout (genuine offsetof values) -------------------

const OFF_KEY_USAGES: u32 = 336; // u8
const OFF_CERT_LENGTH: u32 = 348; // u32
const OFF_NUM_CERTS: u32 = 352; // u32
const OFF_PAD: u32 = 376; // 256 bytes
const OFF_EE_PKEY_DATA: u32 = 632; // BR_X509_BUFSIZE_KEY
const OFF_PKEY_DATA: u32 = 1152; // BR_X509_BUFSIZE_KEY
const OFF_CERT_SIGNER_KEY_TYPE: u32 = 1672; // u8
const OFF_CERT_SIG_HASH_OID: u32 = 1674; // u16
const OFF_CERT_SIG_HASH_LEN: u32 = 1676; // u8
const OFF_CERT_SIG: u32 = 1677; // BR_X509_BUFSIZE_SIG
const OFF_CERT_SIG_LEN: u32 = 2190; // u16
const OFF_MIN_RSA_SIZE: u32 = 2192; // i16
const OFF_DO_MHASH: u32 = 2216; // u8
const OFF_TBS_HASH: u32 = 2640; // 64 bytes
const OFF_DO_DN_HASH: u32 = 2704; // u8
const OFF_CURRENT_DN_HASH: u32 = 2928; // 64 bytes
const OFF_NEXT_DN_HASH: u32 = 2992; // 64 bytes
const OFF_SAVED_DN_HASH: u32 = 3056; // 64 bytes
const MEM_LEN: usize = 3176;

/// The "minimal" X.509 engine context (`br_x509_minimal_context`).
///
/// `'a` is the lifetime of the borrowed configuration: trust anchors, name
/// elements, and the server name.
pub struct br_x509_minimal_context<'a> {
    /// Decoded EE public key (valid on success / not-trusted with a key).
    pub pkey: br_x509_pkey,
    /// Error / status code (0 while running).
    pub err: i32,

    /// Flat byte buffer for byte-addressed fields (see `OFF_*`).
    mem: Box<[u8; MEM_LEN]>,

    // T0 VM state.
    dp_stack: [u32; 31],
    rp_stack: [u32; 31],
    dp: usize,
    rp: usize,
    ip: usize,

    // Current input chunk.
    hlen: usize,
    cur_pos: usize,

    // Server name to match (SAN dNSName / CN).
    server_name: Option<&'a str>,

    // Explicit validation date/time.
    days: u32,
    seconds: u32,

    // Number of certificates processed (mirrors num_certs in mem too).
    cert_length: u32,

    // Trust anchors.
    trust_anchors: &'a [br_x509_trust_anchor<'a>],

    // TBS multi-hasher.
    mhash: br_multihash_context,

    // DN hasher.
    dn_hash_impl: &'static br_hash_class,
    dn_hash: Option<Box<dyn crate::hash::HashState>>,

    // Name elements to gather.
    name_elts: Option<&'a mut [br_name_element<'a>]>,

    // Time callback.
    itime: Option<&'a dyn Fn(u32, u32, u32, u32) -> i32>,

    // Signature verification implementations.
    irsa: Option<br_rsa_pkcs1_vrfy>,
    iecdsa: Option<br_ecdsa_vrfy>,
    iec: Option<&'static br_ec_impl>,
}

#[inline]
fn dnhash_len(impl_: &br_hash_class) -> usize {
    ((impl_.desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK) as usize
}

impl<'a> br_x509_minimal_context<'a> {
    #[inline]
    fn get8(&self, addr: u32) -> u8 {
        self.mem[addr as usize]
    }
    #[inline]
    fn set8(&mut self, addr: u32, v: u8) {
        self.mem[addr as usize] = v;
    }
    #[inline]
    fn get16(&self, addr: u32) -> u16 {
        let a = addr as usize;
        u16::from_le_bytes([self.mem[a], self.mem[a + 1]])
    }
    #[inline]
    fn set16(&mut self, addr: u32, v: u16) {
        self.mem[addr as usize..addr as usize + 2].copy_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn get32(&self, addr: u32) -> u32 {
        let a = addr as usize;
        u32::from_le_bytes([self.mem[a], self.mem[a + 1], self.mem[a + 2], self.mem[a + 3]])
    }
    #[inline]
    fn set32(&mut self, addr: u32, v: u32) {
        self.mem[addr as usize..addr as usize + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Hash a DN (trust-anchor or current) into `out`, using the DN hasher.
    fn hash_dn(&self, dn: &[u8], out: &mut [u8]) {
        let mut h = (self.dn_hash_impl.new)();
        h.update(dn);
        h.out(out);
    }

    /// see bearssl_x509.h (`br_x509_minimal_set_rsa`)
    pub fn set_rsa(&mut self, irsa: br_rsa_pkcs1_vrfy) {
        self.irsa = Some(irsa);
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_ecdsa`)
    pub fn set_ecdsa(&mut self, iec: &'static br_ec_impl, iecdsa: br_ecdsa_vrfy) {
        self.iec = Some(iec);
        self.iecdsa = Some(iecdsa);
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_minrsa`)
    pub fn set_minrsa(&mut self, byte_length: i32) {
        self.set16(OFF_MIN_RSA_SIZE, (byte_length - 128) as i16 as u16);
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_time`)
    pub fn set_time(&mut self, days: u32, seconds: u32) {
        self.days = days;
        self.seconds = seconds;
        self.itime = None;
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_time_callback`)
    pub fn set_time_callback(&mut self, itime: &'a dyn Fn(u32, u32, u32, u32) -> i32) {
        self.itime = Some(itime);
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_hash`)
    pub fn set_hash(&mut self, id: i32, impl_: Option<&'static br_hash_class>) {
        br_multihash_setimpl(&mut self.mhash, id, impl_);
    }
    /// see bearssl_x509.h (`br_x509_minimal_set_name_elements`)
    pub fn set_name_elements(&mut self, elts: &'a mut [br_name_element<'a>]) {
        self.name_elts = Some(elts);
    }

    /// Validated key usages (`BR_KEYTYPE_KEYX` / `BR_KEYTYPE_SIGN`).
    pub fn key_usages(&self) -> u8 {
        self.get8(OFF_KEY_USAGES)
    }
}

/// Verify the signature on the current certificate with public key `pk`.
/// Faithful port of the C `verify_signature` static helper. Returns 0 on
/// success or a non-zero `BR_ERR_X509_*` code.
fn verify_signature(ctx: &br_x509_minimal_context, pk: &VerifyKey) -> i32 {
    let kt = ctx.get8(OFF_CERT_SIGNER_KEY_TYPE);
    if (pk.key_type & 0x0F) != kt {
        return BR_ERR_X509_WRONG_KEY_TYPE;
    }
    let sig_len = ctx.get16(OFF_CERT_SIG_LEN) as usize;
    let sig = &ctx.mem[OFF_CERT_SIG as usize..OFF_CERT_SIG as usize + sig_len];
    let hash_oid_off = ctx.get16(OFF_CERT_SIG_HASH_OID) as usize;
    let hash_len = ctx.get8(OFF_CERT_SIG_HASH_LEN) as usize;
    let tbs_hash = &ctx.mem[OFF_TBS_HASH as usize..OFF_TBS_HASH as usize + hash_len];
    match kt {
        BR_KEYTYPE_RSA => {
            let irsa = match ctx.irsa {
                Some(f) => f,
                None => return BR_ERR_X509_UNSUPPORTED,
            };
            let (n, e) = match &pk.key {
                VerifyKeyData::RSA { n, e } => (*n, *e),
                _ => return BR_ERR_X509_UNSUPPORTED,
            };
            let rsa_pk = br_rsa_public_key { n, e };
            // hash_oid: a length-prefixed DER OID lives in the data block; the C
            // passes `&t0_datablock[cert_sig_hash_oid]`. A zero offset means no
            // OID (MD5+SHA-1 case), encoded as the first data-block byte == 0.
            let oid_slice;
            let hash_oid: Option<&[u8]> = if T0_DATABLOCK[hash_oid_off] == 0 {
                None
            } else {
                let l = T0_DATABLOCK[hash_oid_off] as usize;
                oid_slice = &T0_DATABLOCK[hash_oid_off..hash_oid_off + 1 + l];
                Some(oid_slice)
            };
            let mut tmp = [0u8; 64];
            let r = irsa(sig, hash_oid, hash_len, &rsa_pk, &mut tmp[..hash_len]);
            if r != 1 {
                return BR_ERR_X509_BAD_SIGNATURE;
            }
            if tmp[..hash_len] != *tbs_hash {
                return BR_ERR_X509_BAD_SIGNATURE;
            }
            0
        }
        BR_KEYTYPE_EC => {
            let iecdsa = match ctx.iecdsa {
                Some(f) => f,
                None => return BR_ERR_X509_UNSUPPORTED,
            };
            let iec = match ctx.iec {
                Some(c) => c,
                None => return BR_ERR_X509_UNSUPPORTED,
            };
            let (curve, q) = match &pk.key {
                VerifyKeyData::EC { curve, q } => (*curve, *q),
                _ => return BR_ERR_X509_UNSUPPORTED,
            };
            let ec_pk = br_ec_public_key { curve, q };
            let r = iecdsa(iec, tbs_hash, &ec_pk, sig);
            if r != 1 {
                return BR_ERR_X509_BAD_SIGNATURE;
            }
            0
        }
        _ => BR_ERR_X509_UNSUPPORTED,
    }
}

/// A public key view passed to [`verify_signature`] (borrows into the context's
/// buffers or a trust anchor). Mirrors the temporary `br_x509_pkey pk` built by
/// the C `do-rsa-vrfy` / `do-ecdsa-vrfy` / `check-trust-anchor-CA` opcodes.
struct VerifyKey<'k> {
    key_type: u8,
    key: VerifyKeyData<'k>,
}
enum VerifyKeyData<'k> {
    RSA { n: &'k [u8], e: &'k [u8] },
    EC { curve: i32, q: &'k [u8] },
}

include!("minimal_codeblock.rs");

/// see bearssl_x509.h (`br_x509_minimal_init`)
pub fn br_x509_minimal_init<'a>(
    dn_hash_impl: &'static br_hash_class,
    trust_anchors: &'a [br_x509_trust_anchor<'a>],
) -> br_x509_minimal_context<'a> {
    br_x509_minimal_context {
        pkey: br_x509_pkey::None,
        err: 0,
        mem: Box::new([0u8; MEM_LEN]),
        dp_stack: [0; 31],
        rp_stack: [0; 31],
        dp: 0,
        rp: 0,
        ip: 0,
        hlen: 0,
        cur_pos: 0,
        server_name: None,
        days: 0,
        seconds: 0,
        cert_length: 0,
        trust_anchors,
        mhash: br_multihash_context::default(),
        dn_hash_impl,
        dn_hash: None,
        name_elts: None,
        itime: None,
        irsa: None,
        iecdsa: None,
        iec: None,
    }
}

/// see bearssl_x509.h (`br_x509_minimal_init_full`).
///
/// Convenience builder: a minimal X.509 validation engine with SHA-256 DN
/// hashing, the default i31 RSA (PKCS#1 v1.5) and ECDSA verifiers, and all six
/// hash functions activated. (The validation engine still refuses MD5
/// signatures.) Mirrors `x509_minimal_full.c`.
pub fn br_x509_minimal_init_full<'a>(
    trust_anchors: &'a [br_x509_trust_anchor<'a>],
) -> br_x509_minimal_context<'a> {
    use crate::ec::{br_ec_get_default, br_ecdsa_i31_vrfy_asn1};
    use crate::hash::{
        br_md5_vtable, br_sha1_vtable, br_sha224_vtable, br_sha256_vtable, br_sha384_vtable,
        br_sha512_vtable, br_md5_ID, br_sha512_ID,
    };
    use crate::rsa::br_rsa_pkcs1_vrfy_get_default;

    let mut xc = br_x509_minimal_init(&br_sha256_vtable, trust_anchors);
    xc.set_rsa(br_rsa_pkcs1_vrfy_get_default());
    xc.set_ecdsa(br_ec_get_default(), br_ecdsa_i31_vrfy_asn1);
    let hashes: [&'static br_hash_class; 6] = [
        &br_md5_vtable,
        &br_sha1_vtable,
        &br_sha224_vtable,
        &br_sha256_vtable,
        &br_sha384_vtable,
        &br_sha512_vtable,
    ];
    for id in (br_md5_ID as i32)..=(br_sha512_ID as i32) {
        xc.set_hash(id, Some(hashes[(id - 1) as usize]));
    }
    xc
}

impl X509Engine for br_x509_minimal_context<'_> {
    fn start_chain(&mut self, server_name: Option<&str>) {
        // Mirror xm_start_chain: reset name-element statuses, the output key,
        // the certificate counter, the error flag and the VM stacks.
        if let Some(elts) = self.name_elts.as_mut() {
            for ne in elts.iter_mut() {
                ne.status = 0;
                if !ne.buf.is_empty() {
                    ne.buf[0] = 0;
                }
            }
        }
        self.pkey = br_x509_pkey::None;
        self.set32(OFF_NUM_CERTS, 0);
        self.err = 0;
        self.dp = 0;
        self.rp = 0;
        // The C `start_chain` also takes `server_name`, but the matched name must
        // outlive validation (lifetime `'a`), which the trait's erased lifetime
        // cannot express. The server name is therefore configured out of band via
        // [`set_server_name`] and the argument here is ignored. Callers that need
        // server-name matching must call `set_server_name` before `start_chain`.
        let _ = server_name;
        init_main(self);
    }

    fn start_cert(&mut self, length: u32) {
        if self.err != 0 {
            return;
        }
        if length == 0 {
            self.err = BR_ERR_X509_TRUNCATED;
            return;
        }
        self.cert_length = length;
        self.set32(OFF_CERT_LENGTH, length);
    }

    fn append(&mut self, buf: &[u8]) {
        if self.err != 0 {
            return;
        }
        self.hlen = buf.len();
        self.cur_pos = 0;
        run(self, buf);
    }

    fn end_cert(&mut self) {
        if self.err == 0 && self.get32(OFF_CERT_LENGTH) != 0 {
            self.err = BR_ERR_X509_TRUNCATED;
        }
        let n = self.get32(OFF_NUM_CERTS).wrapping_add(1);
        self.set32(OFF_NUM_CERTS, n);
    }

    fn end_chain(&mut self) -> u32 {
        if self.err == 0 {
            if self.get32(OFF_NUM_CERTS) == 0 {
                self.err = BR_ERR_X509_EMPTY_CHAIN;
            } else {
                self.err = BR_ERR_X509_NOT_TRUSTED;
            }
        } else if self.err == BR_ERR_X509_OK {
            return 0;
        }
        self.err as u32
    }

    fn get_pkey(&self, usages: Option<&mut u32>) -> Option<&br_x509_pkey> {
        if self.err == BR_ERR_X509_OK || self.err == BR_ERR_X509_NOT_TRUSTED {
            if let Some(u) = usages {
                *u = self.key_usages() as u32;
            }
            Some(&self.pkey)
        } else {
            None
        }
    }
}

impl<'a> br_x509_minimal_context<'a> {
    /// Set the server name to match (must be called before `start_chain`'s
    /// matching is needed; stored for the lifetime of validation). This mirrors
    /// the `server_name` parameter of `start_chain` while respecting Rust
    /// borrowing: the name is tied to the engine's `'a` lifetime.
    pub fn set_server_name(&mut self, server_name: Option<&'a str>) {
        self.server_name = match server_name {
            Some(s) if !s.is_empty() => Some(s),
            _ => None,
        };
    }
}
