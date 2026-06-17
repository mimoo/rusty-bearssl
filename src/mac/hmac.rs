/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! HMAC (`src/mac/hmac.c`).

use super::block_size;
use crate::hash::{br_digest_size, br_hash_class, HashState};

/// HMAC key context. Holds the precomputed inner/outer block states.
#[derive(Clone)]
pub struct br_hmac_key_context {
    pub dig_vtable: &'static br_hash_class,
    pub ksi: [u8; 64],
    pub kso: [u8; 64],
}

impl Default for br_hmac_key_context {
    fn default() -> Self {
        // Placeholder vtable replaced by br_hmac_key_init; never used as-is.
        br_hmac_key_context {
            dig_vtable: &crate::hash::br_sha256_vtable,
            ksi: [0u8; 64],
            kso: [0u8; 64],
        }
    }
}

/// HMAC computation context.
pub struct br_hmac_context {
    pub dig: Box<dyn HashState>,
    pub kso: [u8; 64],
    pub out_len: usize,
}

fn process_key(dig: &br_hash_class, ks: &mut [u8], key: &[u8], key_len: usize, bb: u8) {
    let mut tmp = [0u8; 256];
    let blen = block_size(dig);
    tmp[..key_len].copy_from_slice(&key[..key_len]);
    for u in 0..key_len {
        tmp[u] ^= bb;
    }
    for b in tmp[key_len..blen].iter_mut() {
        *b = bb;
    }
    let mut hc = (dig.new)();
    hc.update(&tmp[..blen]);
    hc.state(ks);
}

/// see bearssl.h
pub fn br_hmac_key_init(
    kc: &mut br_hmac_key_context,
    dig: &'static br_hash_class,
    key: &[u8],
    key_len: usize,
) {
    let mut kbuf = [0u8; 64];
    kc.dig_vtable = dig;
    let (key, key_len): (&[u8], usize) = if key_len > block_size(dig) {
        let mut hc = (dig.new)();
        hc.update(&key[..key_len]);
        hc.out(&mut kbuf);
        (&kbuf, br_digest_size(dig))
    } else {
        (key, key_len)
    };
    let mut ksi = [0u8; 64];
    let mut kso = [0u8; 64];
    process_key(dig, &mut ksi, key, key_len, 0x36);
    process_key(dig, &mut kso, key, key_len, 0x5C);
    kc.ksi = ksi;
    kc.kso = kso;
}

/// Get the underlying hash function (inc/bearssl_hmac.h `br_hmac_key_get_digest`).
pub fn br_hmac_key_get_digest(kc: &br_hmac_key_context) -> &'static br_hash_class {
    kc.dig_vtable
}

/// see bearssl.h
pub fn br_hmac_init(ctx: &mut br_hmac_context, kc: &br_hmac_key_context, out_len: usize) {
    let dig = kc.dig_vtable;
    let blen = block_size(dig);
    let mut d = (dig.new)();
    d.set_state(&kc.ksi, blen as u64);
    ctx.dig = d;
    ctx.kso = kc.kso;
    let mut hlen = br_digest_size(dig);
    if out_len > 0 && out_len < hlen {
        hlen = out_len;
    }
    ctx.out_len = hlen;
}

impl br_hmac_context {
    /// Allocate an uninitialised HMAC context; `br_hmac_init` must be called
    /// before use. Provided so callers can stack a context like in C.
    pub fn new(kc: &br_hmac_key_context, out_len: usize) -> Self {
        let mut ctx = br_hmac_context {
            dig: (kc.dig_vtable.new)(),
            kso: [0u8; 64],
            out_len: 0,
        };
        br_hmac_init(&mut ctx, kc, out_len);
        ctx
    }
}

/// see bearssl.h
pub fn br_hmac_update(ctx: &mut br_hmac_context, data: &[u8], len: usize) {
    ctx.dig.update(&data[..len]);
}

/// HMAC output length for the context (inc/bearssl_hmac.h `br_hmac_size`).
pub fn br_hmac_size(ctx: &br_hmac_context) -> usize {
    ctx.out_len
}

/// Get the underlying hash function of a running HMAC context
/// (inc/bearssl_hmac.h `br_hmac_get_digest`).
pub fn br_hmac_get_digest(ctx: &br_hmac_context) -> &'static br_hash_class {
    ctx.dig.vtable()
}

/// see bearssl.h
pub fn br_hmac_out(ctx: &br_hmac_context, out: &mut [u8]) -> usize {
    let dig = ctx.dig.vtable();
    let mut tmp = [0u8; 64];
    ctx.dig.out(&mut tmp);
    let blen = block_size(dig);
    let mut hc = (dig.new)();
    hc.set_state(&ctx.kso, blen as u64);
    let hlen = br_digest_size(dig);
    hc.update(&tmp[..hlen]);
    hc.out(&mut tmp);
    out[..ctx.out_len].copy_from_slice(&tmp[..ctx.out_len]);
    ctx.out_len
}
