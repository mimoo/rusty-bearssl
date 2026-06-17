/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! The SSL/TLS engine (`src/ssl/ssl_engine.c`).
//!
//! This is the core record-layer state machine shared by the client and the
//! server. It manages the input/output buffers, the record framing, the
//! incoming/outgoing dispatch to the handshake processor, alert handling and
//! the key-schedule plumbing (PRF selection + record-layer switch functions).
//!
//! ## Memory model
//!
//! The C `br_ssl_engine_context` is a single big struct whose fields are
//! reached two ways: directly from C engine code, and *by byte offset* from
//! the T0 handshake interpreter (opcodes `get8`/`set32`/`memcpy`/...). To stay
//! faithful while remaining safe Rust, the data fields that the T0 code
//! addresses by offset live in a flat `mem[]` buffer at the genuine upstream
//! `offsetof` values (see the `OFF_*` constants); the pointer/structured
//! fields that only named C helpers touch are held as ordinary Rust fields.
//! This mirrors the approach used by `src/x509/x509_minimal.rs`.

use crate::hash::{
    br_ghash, br_md5_ID, br_multihash_context, br_multihash_getimpl, br_multihash_init,
    br_sha1_ID, br_sha256_ID, br_sha384_ID,
};
use crate::inner::{br_dec16be, br_enc16be};
use crate::rand::{br_hmac_drbg_context, br_hmac_drbg_init, br_hmac_drbg_update};
use crate::ssl::{
    br_sslrec_chapol_context, br_sslrec_gcm_context, br_tls_prf_impl, br_tls_prf_seed_chunk,
    chapol_check_length, chapol_decrypt, chapol_encrypt, chapol_max_plaintext, gcm_check_length,
    gcm_decrypt, gcm_encrypt, gcm_max_plaintext,
};
use crate::symcipher::{br_block_ctr_class, br_chacha20_run};

// ---- protocol versions / record types / errors -----------------------------

pub const BR_SSL30: u16 = 0x0300;
pub const BR_TLS10: u16 = 0x0301;
pub const BR_TLS11: u16 = 0x0302;
pub const BR_TLS12: u16 = 0x0303;

pub const BR_ERR_OK: i32 = 0;
pub const BR_ERR_BAD_PARAM: i32 = 1;
pub const BR_ERR_BAD_STATE: i32 = 2;
pub const BR_ERR_UNSUPPORTED_VERSION: i32 = 3;
pub const BR_ERR_BAD_VERSION: i32 = 4;
pub const BR_ERR_BAD_LENGTH: i32 = 5;
pub const BR_ERR_TOO_LARGE: i32 = 6;
pub const BR_ERR_BAD_MAC: i32 = 7;
pub const BR_ERR_NO_RANDOM: i32 = 8;
pub const BR_ERR_UNKNOWN_TYPE: i32 = 9;
pub const BR_ERR_UNEXPECTED: i32 = 10;
pub const BR_ERR_BAD_CCS: i32 = 12;
pub const BR_ERR_BAD_ALERT: i32 = 13;
pub const BR_ERR_BAD_HANDSHAKE: i32 = 14;
pub const BR_ERR_OVERSIZED_ID: i32 = 15;
pub const BR_ERR_BAD_CIPHER_SUITE: i32 = 16;
pub const BR_ERR_BAD_COMPRESSION: i32 = 17;
pub const BR_ERR_BAD_FRAGLEN: i32 = 18;
pub const BR_ERR_BAD_SECRENEG: i32 = 19;
pub const BR_ERR_EXTRA_EXTENSION: i32 = 20;
pub const BR_ERR_BAD_SNI: i32 = 21;
pub const BR_ERR_BAD_HELLO_DONE: i32 = 22;
pub const BR_ERR_LIMIT_EXCEEDED: i32 = 23;
pub const BR_ERR_BAD_FINISHED: i32 = 24;
pub const BR_ERR_RESUME_MISMATCH: i32 = 25;
pub const BR_ERR_INVALID_ALGORITHM: i32 = 26;
pub const BR_ERR_BAD_SIGNATURE: i32 = 27;
pub const BR_ERR_WRONG_KEY_USAGE: i32 = 28;
pub const BR_ERR_NO_CLIENT_AUTH: i32 = 29;
pub const BR_ERR_IO: i32 = 31;
pub const BR_ERR_RECV_FATAL_ALERT: i32 = 256;
pub const BR_ERR_SEND_FATAL_ALERT: i32 = 512;

/// Record types.
pub const BR_SSL_CHANGE_CIPHER_SPEC: u8 = 20;
pub const BR_SSL_ALERT: u8 = 21;
pub const BR_SSL_HANDSHAKE: u8 = 22;
pub const BR_SSL_APPLICATION_DATA: u8 = 23;

/// I/O modes.
pub const BR_IO_FAILED: u8 = 0;
pub const BR_IO_IN: u8 = 1;
pub const BR_IO_OUT: u8 = 2;
pub const BR_IO_INOUT: u8 = 3;

/// Engine "current state" flags (`br_ssl_engine_current_state`).
pub const BR_SSL_CLOSED: u32 = 0x0001;
pub const BR_SSL_SENDREC: u32 = 0x0002;
pub const BR_SSL_RECVREC: u32 = 0x0004;
pub const BR_SSL_SENDAPP: u32 = 0x0008;
pub const BR_SSL_RECVAPP: u32 = 0x0010;

/// Behavioural flags.
pub const BR_OPT_ENFORCE_SERVER_PREFERENCES: u32 = 1 << 0;
pub const BR_OPT_NO_RENEGOTIATION: u32 = 1 << 1;
pub const BR_OPT_TOLERATE_NO_CLIENT_AUTH: u32 = 1 << 2;
pub const BR_OPT_FAIL_ON_ALPN_MISMATCH: u32 = 1 << 3;

/// PRF selectors used by the key-export API.
pub const BR_SSLPRF_SHA256: i32 = 4;
pub const BR_SSLPRF_SHA384: i32 = 5;

pub const BR_MAX_CIPHER_SUITES: usize = 48;

pub const BR_SSL_BUFSIZE_INPUT: usize = 16384 + 325;
pub const BR_SSL_BUFSIZE_OUTPUT: usize = 16384 + 85;
pub const BR_SSL_BUFSIZE_MONO: usize = BR_SSL_BUFSIZE_INPUT;
pub const BR_SSL_BUFSIZE_BIDI: usize = BR_SSL_BUFSIZE_INPUT + BR_SSL_BUFSIZE_OUTPUT;

const MAX_OUT_OVERHEAD: usize = 85;
const MAX_IN_OVERHEAD: usize = 325;

// ---- genuine offsetof(br_ssl_engine_context, ...) values (64-bit build) -----
//
// These reproduce the exact upstream byte layout, so the T0 codeblock (which
// bakes these same offsets in via `T0_INT2(offsetof(...))`) can be ported
// verbatim. The `mem[]` buffer holds the data fields the T0 code addresses by
// offset; the remaining (pointer / structured) fields are Rust fields. Only the
// offsets used by the byte-addressed opcodes need a `mem[]` slot.

pub(super) const OFF_MAX_FRAG_LEN: usize = 40; // u16
pub(super) const OFF_LOG_MAX_FRAG_LEN: usize = 42; // u8
pub(super) const OFF_PEER_LOG_MAX_FRAG_LEN: usize = 43; // u8
pub(super) const OFF_RECORD_TYPE_IN: usize = 99; // u8
pub(super) const OFF_RECORD_TYPE_OUT: usize = 100; // u8
pub(super) const OFF_VERSION_IN: usize = 102; // u16
pub(super) const OFF_VERSION_OUT: usize = 104; // u16
pub(super) const OFF_APPLICATION_DATA: usize = 1280; // u8
pub(super) const OFF_VERSION_MIN: usize = 1440; // u16
pub(super) const OFF_VERSION_MAX: usize = 1442; // u16
pub(super) const OFF_SUITES_BUF: usize = 1444; // u16[48]
pub(super) const OFF_SUITES_NUM: usize = 1540; // u8
pub(super) const OFF_SERVER_NAME: usize = 1541; // char[256]
pub(super) const OFF_CLIENT_RANDOM: usize = 1797; // u8[32]
pub(super) const OFF_SERVER_RANDOM: usize = 1829; // u8[32]
pub(super) const OFF_SESSION: usize = 1862; // br_ssl_session_parameters
pub(super) const OFF_SESSION_ID: usize = OFF_SESSION; // u8[32]
pub(super) const OFF_SESSION_ID_LEN: usize = OFF_SESSION + 32; // u8
pub(super) const OFF_SESSION_VERSION: usize = OFF_SESSION + 34; // u16
pub(super) const OFF_SESSION_CIPHER_SUITE: usize = OFF_SESSION + 36; // u16
pub(super) const OFF_SESSION_MASTER_SECRET: usize = OFF_SESSION + 38; // u8[48]
pub(super) const OFF_ECDHE_CURVE: usize = 1948; // u8
pub(super) const OFF_ECDHE_POINT: usize = 1949; // u8[133]
pub(super) const OFF_ECDHE_POINT_LEN: usize = 2082; // u8
pub(super) const OFF_RENEG: usize = 2083; // u8
pub(super) const OFF_SAVED_FINISHED: usize = 2084; // u8[24]
pub(super) const OFF_FLAGS: usize = 2108; // u32
pub(super) const OFF_PAD: usize = 2392; // u8[512]
pub(super) const OFF_ALERT: usize = 2953; // u8
pub(super) const OFF_CLOSE_RECEIVED: usize = 2954; // u8
pub(super) const OFF_SELECTED_PROTOCOL: usize = 3426; // u16

// Client-context-specific addressable fields (offsets within br_ssl_client_context).
pub(super) const OFF_CLI_MIN_CLIENTHELLO_LEN: usize = 3616; // u16
pub(super) const OFF_CLI_SERVER_CURVE: usize = 3624; // i32
pub(super) const OFF_CLI_AUTH_TYPE: usize = 3640; // u8
pub(super) const OFF_CLI_HASH_ID: usize = 3641; // u8

/// Size of the flat memory buffer: enough to cover every addressable field.
/// We size it to hold the client context fields too (the T0 client code uses
/// `br_ssl_client_context` offsets, which extend past the engine struct).
pub(super) const MEM_LEN: usize = 3720;

pub const BR_SSL_PAD_LEN: usize = 512;

// ---- record handlers (model the C union of in/out record contexts) ---------

/// Incoming record decryption handler. `None`/`Clear` means no decryption.
pub(super) enum InRec {
    /// No active decryption (handshake before first CCS): records are read in
    /// place with only header framing.
    Clear,
    Gcm(br_sslrec_gcm_context),
    Chapol(br_sslrec_chapol_context),
}

/// Outgoing record encryption handler.
pub(super) enum OutRec {
    Clear,
    Gcm(br_sslrec_gcm_context),
    Chapol(br_sslrec_chapol_context),
}

impl InRec {
    fn check_length(&self, rlen: usize) -> bool {
        match self {
            InRec::Clear => rlen <= 16384,
            InRec::Gcm(cc) => gcm_check_length(cc, rlen),
            InRec::Chapol(cc) => chapol_check_length(cc, rlen),
        }
    }
}

impl OutRec {
    fn max_plaintext(&self, start: &mut usize, end: &mut usize) {
        match self {
            OutRec::Clear => {
                let len = *end - *start;
                if len > 16384 {
                    *end = *start + 16384;
                }
            }
            OutRec::Gcm(cc) => gcm_max_plaintext(cc, start, end),
            OutRec::Chapol(cc) => chapol_max_plaintext(cc, start, end),
        }
    }
}

// ---- the engine context -----------------------------------------------------

/// SSL engine context (`br_ssl_engine_context`).
///
/// Holds the configuration, buffers and record state. The big flat `mem[]`
/// buffer carries the T0-addressable data fields at genuine upstream offsets.
pub struct br_ssl_engine_context {
    pub err: i32,

    /// Input and output buffers (may be the same allocation, modelled as
    /// disjoint owned vectors here; shared-buffer mode is selected by a flag).
    pub(super) ibuf: Vec<u8>,
    pub(super) obuf: Vec<u8>,
    pub(super) shared_io: bool,

    pub(super) ixa: usize,
    pub(super) ixb: usize,
    pub(super) ixc: usize,
    pub(super) oxa: usize,
    pub(super) oxb: usize,
    pub(super) oxc: usize,
    pub(super) iomode: u8,
    pub(super) incrypt: bool,
    pub(super) shutdown_recv: bool,

    /// Flat byte buffer holding all T0-addressed data fields (see `OFF_*`).
    pub(super) mem: Box<[u8; MEM_LEN]>,

    /// Record handlers.
    pub(super) in_rec: InRec,
    pub(super) out_rec: OutRec,

    /// RNG (initialised lazily by `rng_init`; `None` until then).
    pub rng: Option<br_hmac_drbg_context>,
    pub(super) rng_init_done: i32,
    pub(super) rng_os_rand_done: bool,

    /// Handshake processor coupling.
    pub(super) hbuf_in_off: usize,
    pub(super) hbuf_in_owner: HBuf,
    pub(super) hbuf_out_off: usize,
    pub(super) saved_hbuf_out_off: usize,
    pub(super) hlen_in: usize,
    pub(super) hlen_out: usize,
    pub(super) action: u8,

    /// Multi-hasher for handshake messages.
    pub mhash: br_multihash_context,

    /// PRF implementations.
    pub(super) prf10: Option<br_tls_prf_impl>,
    pub(super) prf_sha256: Option<br_tls_prf_impl>,
    pub(super) prf_sha384: Option<br_tls_prf_impl>,

    /// Symmetric/AEAD implementation hooks.
    pub(super) iaes_ctr: Option<&'static br_block_ctr_class>,
    pub(super) ighash: Option<br_ghash>,
    pub(super) ichacha: Option<br_chacha20_run>,
    pub(super) ipoly: Option<crate::ssl::br_poly1305_run>,
    /// Record-layer availability flags (mirror the `i*_in/out` vtable pointers).
    pub(super) has_gcm: bool,
    pub(super) has_chapol: bool,

    /// EC / signature verification implementations.
    pub(super) iec: Option<&'static crate::ec::br_ec_impl>,
    pub(super) irsavrfy: Option<crate::rsa::br_rsa_pkcs1_vrfy>,
    pub(super) iecdsa: Option<crate::ec::br_ecdsa_vrfy>,

    /// X.509 validation engine (set by the application).
    pub(super) x509: Option<Box<dyn crate::x509::X509Engine>>,

    /// Certificate chain to send.
    pub(super) chain: Vec<Vec<u8>>,
    pub(super) chain_idx: usize,
    pub(super) cert_cur: Vec<u8>,
    pub(super) cert_pos: usize,

    /// Closure flags / alert mirror (also in mem for T0).
    pub(super) close_received: bool,

    /// Handshake entry/run callbacks (filled by client/server reset).
    pub(super) hsrun: Option<HsKind>,
}

/// Which buffer the handshake input pointer currently refers to.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum HBuf {
    None,
    Input,
}

/// Selects which T0 handshake program drives the engine.
#[derive(Clone, Copy)]
pub(super) enum HsKind {
    Client,
    Server,
}

impl br_ssl_engine_context {
    // ---- mem[] accessors (genuine-offset byte access) -----------------------

    #[inline]
    pub(super) fn get8(&self, addr: usize) -> u8 {
        self.mem[addr]
    }
    #[inline]
    pub(super) fn set8(&mut self, addr: usize, v: u8) {
        self.mem[addr] = v;
    }
    #[inline]
    pub(super) fn get16(&self, addr: usize) -> u16 {
        u16::from_ne_bytes([self.mem[addr], self.mem[addr + 1]])
    }
    #[inline]
    pub(super) fn set16(&mut self, addr: usize, v: u16) {
        self.mem[addr..addr + 2].copy_from_slice(&v.to_ne_bytes());
    }
    #[inline]
    pub(super) fn get32(&self, addr: usize) -> u32 {
        u32::from_ne_bytes([
            self.mem[addr],
            self.mem[addr + 1],
            self.mem[addr + 2],
            self.mem[addr + 3],
        ])
    }
    #[inline]
    pub(super) fn set32(&mut self, addr: usize, v: u32) {
        self.mem[addr..addr + 4].copy_from_slice(&v.to_ne_bytes());
    }

    // ---- convenience accessors for engine code ------------------------------

    #[inline]
    pub(super) fn version_in(&self) -> u16 {
        self.get16(OFF_VERSION_IN)
    }
    #[inline]
    pub(super) fn set_version_in(&mut self, v: u16) {
        self.set16(OFF_VERSION_IN, v)
    }
    #[inline]
    pub(super) fn version_out(&self) -> u16 {
        self.get16(OFF_VERSION_OUT)
    }
    #[inline]
    pub(super) fn record_type_in(&self) -> u8 {
        self.get8(OFF_RECORD_TYPE_IN)
    }
    #[inline]
    pub(super) fn set_record_type_in(&mut self, v: u8) {
        self.set8(OFF_RECORD_TYPE_IN, v)
    }
    #[inline]
    pub(super) fn record_type_out(&self) -> u8 {
        self.get8(OFF_RECORD_TYPE_OUT)
    }
    #[inline]
    pub(super) fn application_data(&self) -> u8 {
        self.get8(OFF_APPLICATION_DATA)
    }
    #[inline]
    pub(super) fn set_application_data(&mut self, v: u8) {
        self.set8(OFF_APPLICATION_DATA, v)
    }
    #[inline]
    pub(super) fn max_frag_len(&self) -> usize {
        self.get16(OFF_MAX_FRAG_LEN) as usize
    }
    #[inline]
    pub(super) fn reneg(&self) -> u8 {
        self.get8(OFF_RENEG)
    }
    #[inline]
    pub fn flags(&self) -> u32 {
        self.get32(OFF_FLAGS)
    }

    pub(super) fn ibuf_len(&self) -> usize {
        self.ibuf.len()
    }
    pub(super) fn obuf_len(&self) -> usize {
        self.obuf.len()
    }

    /// see inner.h (`br_ssl_engine_fail`)
    pub fn fail(&mut self, err: i32) {
        if self.iomode != BR_IO_FAILED {
            self.iomode = BR_IO_FAILED;
            self.err = err;
        }
    }

    /// see bearssl_ssl.h (`br_ssl_engine_closed`)
    pub fn closed(&self) -> bool {
        self.iomode == BR_IO_FAILED
    }

    /// see bearssl_ssl.h (`br_ssl_engine_last_error`)
    pub fn last_error(&self) -> i32 {
        self.err
    }
}

impl br_ssl_engine_context {
    /// Create a zeroed engine context (`memset(cc, 0, sizeof *cc)` equivalent).
    pub(super) fn new() -> Self {
        br_ssl_engine_context {
            err: 0,
            ibuf: Vec::new(),
            obuf: Vec::new(),
            shared_io: false,
            ixa: 0,
            ixb: 0,
            ixc: 0,
            oxa: 0,
            oxb: 0,
            oxc: 0,
            iomode: BR_IO_FAILED,
            incrypt: false,
            shutdown_recv: false,
            mem: Box::new([0u8; MEM_LEN]),
            in_rec: InRec::Clear,
            out_rec: OutRec::Clear,
            rng: None,
            rng_init_done: 0,
            rng_os_rand_done: false,
            hbuf_in_off: 0,
            hbuf_in_owner: HBuf::None,
            hbuf_out_off: 0,
            saved_hbuf_out_off: 0,
            hlen_in: 0,
            hlen_out: 0,
            action: 0,
            mhash: br_multihash_context::default(),
            prf10: None,
            prf_sha256: None,
            prf_sha384: None,
            iaes_ctr: None,
            ighash: None,
            ichacha: None,
            ipoly: None,
            has_gcm: false,
            has_chapol: false,
            iec: None,
            irsavrfy: None,
            iecdsa: None,
            x509: None,
            chain: Vec::new(),
            chain_idx: 0,
            cert_cur: Vec::new(),
            cert_pos: 0,
            close_received: false,
            hsrun: None,
        }
    }
}

include!("ssl_engine_io.rs");
include!("ssl_engine_keys.rs");
include!("ssl_engine_api.rs");
