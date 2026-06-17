/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! HMAC_DRBG (`src/rand/hmac_drbg.c`), the HMAC-based DRBG from NIST SP800-90A.

use super::{br_prng_class, PrngState};
use crate::hash::{br_digest_size, br_hash_class};
use crate::mac::{
    br_hmac_context, br_hmac_init, br_hmac_key_context, br_hmac_key_init, br_hmac_out,
    br_hmac_update,
};

/// HMAC_DRBG context.
pub struct br_hmac_drbg_context {
    pub vtable: &'static br_prng_class,
    pub K: [u8; 64],
    pub V: [u8; 64],
    pub digest_class: &'static br_hash_class,
}

/// see bearssl.h
pub fn br_hmac_drbg_init(
    ctx: &mut br_hmac_drbg_context,
    digest_class: &'static br_hash_class,
    seed: &[u8],
    len: usize,
) {
    ctx.vtable = &br_hmac_drbg_vtable;
    let hlen = br_digest_size(digest_class);
    for b in ctx.K[..hlen].iter_mut() {
        *b = 0x00;
    }
    for b in ctx.V[..hlen].iter_mut() {
        *b = 0x01;
    }
    ctx.digest_class = digest_class;
    br_hmac_drbg_update(ctx, seed, len);
}

/// see bearssl.h
pub fn br_hmac_drbg_generate(ctx: &mut br_hmac_drbg_context, out: &mut [u8], len: usize) {
    let dig = ctx.digest_class;
    let hlen = br_digest_size(dig);
    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, dig, &ctx.K, hlen);

    let mut off = 0usize;
    let mut len = len;
    while len > 0 {
        let mut hc = br_hmac_context::new(&kc, 0);
        let v = ctx.V;
        br_hmac_update(&mut hc, &v, hlen);
        br_hmac_out(&hc, &mut ctx.V);
        let mut clen = hlen;
        if clen > len {
            clen = len;
        }
        out[off..off + clen].copy_from_slice(&ctx.V[..clen]);
        off += clen;
        len -= clen;
    }

    // Inlined update() with an empty additional seed, reusing kc.
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_update(&mut hc, &[0x00], 1);
    br_hmac_out(&hc, &mut ctx.K);
    br_hmac_key_init(&mut kc, dig, &ctx.K, hlen);
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_out(&hc, &mut ctx.V);
}

/// see bearssl.h
pub fn br_hmac_drbg_update(ctx: &mut br_hmac_drbg_context, seed: &[u8], len: usize) {
    let dig = ctx.digest_class;
    let hlen = br_digest_size(dig);

    // 1. K = HMAC(K, V || 0x00 || seed)
    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, dig, &ctx.K, hlen);
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_update(&mut hc, &[0x00], 1);
    br_hmac_update(&mut hc, seed, len);
    br_hmac_out(&hc, &mut ctx.K);
    br_hmac_key_init(&mut kc, dig, &ctx.K, hlen);

    // 2. V = HMAC(K, V)
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_out(&hc, &mut ctx.V);

    // 3. If the additional seed is empty, stop here.
    if len == 0 {
        return;
    }

    // 4. K = HMAC(K, V || 0x01 || seed)
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_update(&mut hc, &[0x01], 1);
    br_hmac_update(&mut hc, seed, len);
    br_hmac_out(&hc, &mut ctx.K);
    br_hmac_key_init(&mut kc, dig, &ctx.K, hlen);

    // 5. V = HMAC(K, V)
    let mut hc = br_hmac_context::new(&kc, 0);
    let v = ctx.V;
    br_hmac_update(&mut hc, &v, hlen);
    br_hmac_out(&hc, &mut ctx.V);
}

impl br_hmac_drbg_context {
    /// Create and seed a new HMAC_DRBG context.
    pub fn new(digest_class: &'static br_hash_class, seed: &[u8]) -> Self {
        let mut ctx = br_hmac_drbg_context {
            vtable: &br_hmac_drbg_vtable,
            K: [0u8; 64],
            V: [0u8; 64],
            digest_class,
        };
        br_hmac_drbg_init(&mut ctx, digest_class, seed, seed.len());
        ctx
    }
}

impl PrngState for br_hmac_drbg_context {
    fn generate(&mut self, out: &mut [u8]) {
        let n = out.len();
        br_hmac_drbg_generate(self, out, n);
    }
    fn update(&mut self, seed: &[u8]) {
        br_hmac_drbg_update(self, seed, seed.len());
    }
}

/// see bearssl.h
pub static br_hmac_drbg_vtable: br_prng_class = br_prng_class {
    context_size: std::mem::size_of::<br_hmac_drbg_context>(),
    init: |params, seed| Box::new(br_hmac_drbg_context::new(params, seed)),
};
