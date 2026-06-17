/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `x509_decoder.c`.)
 */

//! Single-certificate X.509 decoder (`src/x509/x509_decoder.c`).
//!
//! Extracts the subject DN (via callback) and the public key from a DER-encoded
//! certificate. This is *not* a validating engine; it is used, for instance, to
//! turn a self-signed certificate into a trust anchor.
//!
//! The T0 interpreter and code/data blocks are ported faithfully from the
//! generated C. Context fields that the C code addresses by `offsetof` are laid
//! out in a flat byte array (`mem`); the `OFF_*` constants below are baked into
//! the code block exactly where the C source used `offsetof(...)`.

use crate::x509::br_x509_pkey;
use crate::x509::t0::*;

// ---- addressable context layout --------------------------------------------
//
// These are the genuine `offsetof(br_x509_decoder_context, field)` values from
// the upstream C struct, so the generated code block (which bakes
// `offsetof(...)` into its bytes) is reproduced verbatim. The flat `mem[]`
// buffer is sized to `sizeof(br_x509_decoder_context)`; the T0 code only
// byte-addresses the fields below (the lowest is `decoded` at 580), so the
// low region overlapping `pkey`/`cpu`/stacks/`err` is never touched.

const OFF_DECODED: u32 = 580; // u8
const OFF_NOTBEFORE_DAYS: u32 = 584; // u32
const OFF_NOTBEFORE_SECONDS: u32 = 588; // u32
const OFF_NOTAFTER_DAYS: u32 = 592; // u32
const OFF_NOTAFTER_SECONDS: u32 = 596; // u32
const OFF_ISCA: u32 = 600; // u8
const OFF_COPY_DN: u32 = 601; // u8
const OFF_PAD: u32 = 324; // 256 bytes
const OFF_PKEY_DATA: u32 = 640; // BR_X509_BUFSIZE_KEY bytes
const OFF_SIGNER_KEY_TYPE: u32 = 1160; // u8
const OFF_SIGNER_HASH_ID: u32 = 1161; // u8
const MEM_LEN: usize = 1168;

// ---- public context ---------------------------------------------------------

/// X.509 decoder context (`br_x509_decoder_context`).
///
/// `'a` is the lifetime of the optional subject-DN receiver callback.
pub struct br_x509_decoder_context<'a> {
    /// Decoded public key (valid once `decoded()` and `err == 0`).
    pub pkey: br_x509_pkey,
    /// Error code (0 = none yet).
    pub err: i32,

    append_dn: Option<&'a mut dyn FnMut(&[u8])>,

    /// Flat byte buffer for all T0-addressable fields (see `OFF_*`).
    mem: Box<[u8; MEM_LEN]>,

    // T0 VM state.
    dp_stack: [u32; 32],
    rp_stack: [u32; 32],
    dp: usize,
    rp: usize,
    ip: usize,

    // Current input chunk position (the chunk slice is threaded through `run`).
    hlen: usize,
    cur_pos: usize,
}

impl br_x509_decoder_context<'_> {
    #[inline]
    fn get8(&self, addr: u32) -> u8 {
        self.mem[addr as usize]
    }
    #[inline]
    fn set8(&mut self, addr: u32, v: u8) {
        self.mem[addr as usize] = v;
    }
    #[inline]
    fn set32(&mut self, addr: u32, v: u32) {
        self.mem[addr as usize..addr as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn get32(&self, addr: u32) -> u32 {
        let a = addr as usize;
        u32::from_le_bytes([self.mem[a], self.mem[a + 1], self.mem[a + 2], self.mem[a + 3]])
    }

    /// notBefore date (days, seconds).
    pub fn notbefore(&self) -> (u32, u32) {
        (self.get32(OFF_NOTBEFORE_DAYS), self.get32(OFF_NOTBEFORE_SECONDS))
    }
    /// notAfter date (days, seconds).
    pub fn notafter(&self) -> (u32, u32) {
        (self.get32(OFF_NOTAFTER_DAYS), self.get32(OFF_NOTAFTER_SECONDS))
    }
    /// see bearssl_x509.h (`br_x509_decoder_isCA`)
    pub fn isCA(&self) -> bool {
        self.get8(OFF_ISCA) != 0
    }
    /// see bearssl_x509.h (`br_x509_decoder_get_signer_key_type`)
    pub fn signer_key_type(&self) -> u8 {
        self.get8(OFF_SIGNER_KEY_TYPE)
    }
    /// see bearssl_x509.h (`br_x509_decoder_get_signer_hash_id`)
    pub fn signer_hash_id(&self) -> u8 {
        self.get8(OFF_SIGNER_HASH_ID)
    }
    /// Whether decoding completed.
    pub fn decoded(&self) -> bool {
        self.get8(OFF_DECODED) != 0
    }

    /// see bearssl_x509.h (`br_x509_decoder_get_pkey`)
    pub fn get_pkey(&self) -> Option<&br_x509_pkey> {
        if self.decoded() && self.err == 0 {
            Some(&self.pkey)
        } else {
            None
        }
    }

    /// see bearssl_x509.h (`br_x509_decoder_last_error`)
    pub fn last_error(&self) -> i32 {
        if self.err != 0 {
            return self.err;
        }
        if !self.decoded() {
            return BR_ERR_X509_TRUNCATED;
        }
        0
    }
}

include!("decoder_codeblock.rs");

/// see bearssl_x509.h (`br_x509_decoder_init`)
pub fn br_x509_decoder_init(
    append_dn: Option<&mut dyn FnMut(&[u8])>,
) -> br_x509_decoder_context<'_> {
    let mut ctx = br_x509_decoder_context {
        pkey: br_x509_pkey::None,
        err: 0,
        append_dn,
        mem: Box::new([0u8; MEM_LEN]),
        dp_stack: [0; 32],
        rp_stack: [0; 32],
        dp: 0,
        rp: 0,
        ip: 0,
        hlen: 0,
        cur_pos: 0,
    };
    init_main(&mut ctx);
    run(&mut ctx, &[]);
    ctx
}

/// see bearssl_x509.h (`br_x509_decoder_push`)
pub fn br_x509_decoder_push(ctx: &mut br_x509_decoder_context, data: &[u8]) {
    if ctx.err != 0 {
        return;
    }
    ctx.hlen = data.len();
    ctx.cur_pos = 0;
    run(ctx, data);
}
