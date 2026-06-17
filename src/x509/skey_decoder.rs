/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `skey_decoder.c`.)
 */

//! Private key decoder (`src/x509/skey_decoder.c`).
//!
//! Recognises RSA and EC private keys, either in their raw DER-encoded format
//! (PKCS#1 `RSAPrivateKey` / SEC1 `ECPrivateKey`) or wrapped in an unencrypted
//! PKCS#8 archive.
//!
//! The T0 interpreter and code/data blocks are ported faithfully from the
//! generated C, using the genuine upstream `offsetof` values (baked into the
//! code block) and a flat `mem[]` buffer for byte-addressed fields.

use crate::x509::br_skey;
use crate::x509::t0::*;

// ---- addressable context layout (genuine offsetof values) -------------------

const OFF_KEY_TYPE: u32 = 648; // u8
const OFF_KEY_DATA: u32 = 649; // 3 * BR_X509_BUFSIZE_SIG bytes
const OFF_PAD: u32 = 392; // 256 bytes
const MEM_LEN: usize = 2192;

/// Private key decoder context (`br_skey_decoder_context`).
pub struct br_skey_decoder_context {
    /// Decoded private key.
    pub key: br_skey,
    /// Error code (0 = none yet).
    pub err: i32,

    mem: Box<[u8; MEM_LEN]>,

    dp_stack: [u32; 32],
    rp_stack: [u32; 32],
    dp: usize,
    rp: usize,
    ip: usize,

    hlen: usize,
    cur_pos: usize,
}

impl br_skey_decoder_context {
    #[inline]
    fn get8(&self, addr: u32) -> u8 {
        self.mem[addr as usize]
    }
    #[inline]
    fn set8(&mut self, addr: u32, v: u8) {
        self.mem[addr as usize] = v;
    }

    /// see bearssl_x509.h (`br_skey_decoder_key_type`)
    pub fn key_type(&self) -> u8 {
        if self.err == 0 {
            self.get8(OFF_KEY_TYPE)
        } else {
            0
        }
    }

    /// see bearssl_x509.h (`br_skey_decoder_last_error`)
    pub fn last_error(&self) -> i32 {
        if self.err != 0 {
            return self.err;
        }
        if self.get8(OFF_KEY_TYPE) == 0 {
            return BR_ERR_X509_TRUNCATED;
        }
        0
    }

    /// see bearssl_x509.h (`br_skey_decoder_get_rsa`)
    pub fn get_rsa(&self) -> Option<&br_skey> {
        match (&self.key, self.err) {
            (k @ br_skey::RSA { .. }, 0) => Some(k),
            _ => None,
        }
    }
    /// see bearssl_x509.h (`br_skey_decoder_get_ec`)
    pub fn get_ec(&self) -> Option<&br_skey> {
        match (&self.key, self.err) {
            (k @ br_skey::EC { .. }, 0) => Some(k),
            _ => None,
        }
    }
    /// The decoded key (owned), regardless of type.
    pub fn key(&self) -> &br_skey {
        &self.key
    }
}

include!("skey_codeblock.rs");

/// see bearssl_x509.h (`br_skey_decoder_init`)
pub fn br_skey_decoder_init() -> br_skey_decoder_context {
    let mut ctx = br_skey_decoder_context {
        key: br_skey::None,
        err: 0,
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

/// see bearssl_x509.h (`br_skey_decoder_push`)
pub fn br_skey_decoder_push(ctx: &mut br_skey_decoder_context, data: &[u8]) {
    if ctx.err != 0 {
        return;
    }
    ctx.hlen = data.len();
    ctx.cur_pos = 0;
    run(ctx, data);
}
