/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES/CTR DRBG (`src/rand/aesctr_drbg.c`).
//!
//! This is the BearSSL-specific deterministic RNG built on AES-CTR. The state
//! update uses a Hirose-construction hash function over AES-256 (see the
//! comments in [`br_aesctr_drbg_update`]); the output is produced with AES-CTR
//! using a 12-byte IV and a 32-bit block counter.

use super::{br_prng_class, PrngParams, PrngState};
use crate::inner::br_dec32be;
use crate::symcipher::{br_block_ctr_class, Ctr};

/// AES/CTR DRBG context (`br_aesctr_drbg_context`).
///
/// The C struct embeds the AES-CTR subkey context (`sk`). Here we keep the
/// keyed implementation as a `Box<dyn Ctr>` plus the descriptor used to re-key
/// it (the state update repeatedly sets a new AES key).
pub struct br_aesctr_drbg_context {
    pub vtable: &'static br_prng_class,
    pub aesctr: &'static br_block_ctr_class,
    pub sk: Box<dyn Ctr>,
    pub cc: u32,
}

/// see bearssl_rand.h
pub fn br_aesctr_drbg_init(
    aesctr: &'static br_block_ctr_class,
    seed: &[u8],
) -> br_aesctr_drbg_context {
    let tmp = [0u8; 16];
    let mut ctx = br_aesctr_drbg_context {
        vtable: &br_aesctr_drbg_vtable,
        aesctr,
        sk: (aesctr.init)(&tmp),
        cc: 0,
    };
    br_aesctr_drbg_update(&mut ctx, seed);
    ctx
}

/// see bearssl_rand.h
pub fn br_aesctr_drbg_generate(ctx: &mut br_aesctr_drbg_context, out: &mut [u8]) {
    let iv = [0u8; 12];
    let mut off = 0usize;
    let mut len = out.len();
    while len > 0 {
        // We generate data by blocks of at most 65280 bytes. This allows for
        // unambiguously testing the counter overflow condition; also, it should
        // work on 16-bit architectures (where 'size_t' is 16 bits only).
        let mut clen = len;
        if clen > 65280 {
            clen = 65280;
        }

        // We make sure that the counter won't exceed the configured limit.
        if ctx.cc.wrapping_add(((clen + 15) >> 4) as u32) > 32768 {
            clen = ((32768 - ctx.cc) as usize) << 4;
            if clen > len {
                clen = len;
            }
        }

        // Run CTR.
        for b in out[off..off + clen].iter_mut() {
            *b = 0;
        }
        ctx.cc = ctx.sk.run(&iv, ctx.cc, &mut out[off..off + clen]);
        off += clen;
        len -= clen;

        // Every 32768 blocks, we force a state update.
        if ctx.cc >= 32768 {
            br_aesctr_drbg_update(ctx, &[]);
        }
    }
}

/// see bearssl_rand.h
pub fn br_aesctr_drbg_update(ctx: &mut br_aesctr_drbg_context, seed: &[u8]) {
    // We use a Hirose construction on AES-256 to make a hash function.
    // Function definition:
    //  - running state consists in two 16-byte blocks G and H
    //  - initial values of G and H are conventional
    //  - there is a fixed block-sized constant C
    //  - for next data block m:
    //      set AES key to H||m
    //      G' = E(G) xor G
    //      H' = E(G xor C) xor G xor C
    //      G <- G', H <- H'
    //  - once all blocks have been processed, output is H||G
    //
    // Constants:
    //   G_init = B6 B6 ... B6
    //   H_init = A5 A5 ... A5
    //   C      = 01 00 ... 00
    //
    // With this hash function h(), we compute the new state as follows:
    //  - produce a state-dependent value s as encryption of an all-one block
    //    with AES and the current key
    //  - compute the new key as the first 128 bits of h(s||seed)

    // Use an all-one IV to get a fresh output block that depends on the current
    // seed.
    let iv_ff = [0xFFu8; 12];
    let mut s = [0u8; 16];
    ctx.sk.run(&iv_ff, 0xFFFFFFFF, &mut s);

    // Set G[] and H[] to conventional start values.
    let mut g = [0xB6u8; 16];
    let mut h = [0x5Au8; 16];

    // Process the concatenation of the current state and the seed with the
    // custom hash function.
    let mut off = 0usize;
    let mut len = seed.len();
    let mut first = true;
    loop {
        // Assemble new key H||m into tmp[].
        let mut tmp = [0u8; 32];
        tmp[..16].copy_from_slice(&h);
        if first {
            tmp[16..32].copy_from_slice(&s);
            first = false;
        } else {
            if len == 0 {
                break;
            }
            let clen = if len < 16 { len } else { 16 };
            tmp[16..16 + clen].copy_from_slice(&seed[off..off + clen]);
            // remaining bytes already zero
            off += clen;
            len -= clen;
        }
        ctx.sk = (ctx.aesctr.init)(&tmp);

        // Compute new G and H values.
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&g[..12]);
        let mut new_g = g;
        ctx.sk.run(&iv, br_dec32be(&g[12..]), &mut new_g);
        iv[0] ^= 0x01;
        h = g;
        h[0] ^= 0x01;
        ctx.sk.run(&iv, br_dec32be(&g[12..]), &mut h);
        g = new_g;
    }

    // Output hash value is H||G. We truncate it to its first 128 bits, i.e. H;
    // that's our new AES key.
    ctx.sk = (ctx.aesctr.init)(&h);
    ctx.cc = 0;
}

impl br_aesctr_drbg_context {
    /// Create and seed a new AES/CTR DRBG context.
    pub fn new(aesctr: &'static br_block_ctr_class, seed: &[u8]) -> Self {
        br_aesctr_drbg_init(aesctr, seed)
    }
}

impl PrngState for br_aesctr_drbg_context {
    fn generate(&mut self, out: &mut [u8]) {
        br_aesctr_drbg_generate(self, out);
    }
    fn update(&mut self, seed: &[u8]) {
        br_aesctr_drbg_update(self, seed);
    }
}

/// see bearssl_rand.h
pub static br_aesctr_drbg_vtable: br_prng_class = br_prng_class {
    context_size: std::mem::size_of::<br_aesctr_drbg_context>(),
    init: |params, seed| match params {
        PrngParams::BlockCtr(c) => Box::new(br_aesctr_drbg_context::new(c, seed)),
        PrngParams::Hash(_) => panic!("AES/CTR DRBG requires a block-CTR parameter"),
    },
};
