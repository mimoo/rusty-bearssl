/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Multi-hasher (`src/hash/multihash.c`).
//!
//! Runs up to six standard TLS hash functions (MD5, SHA-1, SHA-224, SHA-256,
//! SHA-384, SHA-512) in parallel over the same input.
//!
//! Porting note: the C implementation externalises each running state into a
//! flat `val_32`/`val_64` array and rebuilds a temporary context per 128-byte
//! block (via set_state/update/state). Here we keep one live boxed context per
//! configured implementation and feed them all directly; the observable hash
//! outputs are identical. `br_multihash_out` snapshots (clones) the live
//! context before finalising, so the running computation is not disturbed —
//! matching the C contract that `out` does not modify the context.

use super::*;

/// Multi-hasher context.
#[derive(Default)]
pub struct br_multihash_context {
    pub count: u64,
    /// Configured implementations, indexed by `id - 1` (MD5..SHA-512).
    pub r#impl: [Option<&'static br_hash_class>; 6],
    /// Live running contexts for each configured implementation.
    state: [Option<Box<dyn HashState>>; 6],
}

/// see bearssl_hash.h
pub fn br_multihash_zero(ctx: &mut br_multihash_context) {
    ctx.count = 0;
    ctx.r#impl = [None; 6];
    ctx.state = Default::default();
}

/// see bearssl_hash.h
pub fn br_multihash_setimpl(ctx: &mut br_multihash_context, id: i32, im: Option<&'static br_hash_class>) {
    ctx.r#impl[(id - 1) as usize] = im;
}

/// see bearssl_hash.h
pub fn br_multihash_getimpl(ctx: &br_multihash_context, id: i32) -> Option<&'static br_hash_class> {
    ctx.r#impl[(id - 1) as usize]
}

/// see bearssl_hash.h
pub fn br_multihash_init(ctx: &mut br_multihash_context) {
    ctx.count = 0;
    for i in 0..6 {
        ctx.state[i] = ctx.r#impl[i].map(|hc| (hc.new)());
    }
}

/// see bearssl_hash.h
pub fn br_multihash_update(ctx: &mut br_multihash_context, data: &[u8], len: usize) {
    let data = &data[..len];
    for st in ctx.state.iter_mut() {
        if let Some(h) = st {
            h.update(data);
        }
    }
    ctx.count += len as u64;
}

/// see bearssl_hash.h
pub fn br_multihash_out(ctx: &br_multihash_context, id: i32, dst: &mut [u8]) -> usize {
    match &ctx.state[(id - 1) as usize] {
        Some(h) => {
            let snapshot = h.clone();
            snapshot.out(dst);
            (((h.vtable().desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK)) as usize
        }
        None => 0,
    }
}

/// Copy all configured hash implementations from one context to another
/// (inner.h `br_multihash_copyimpl`).
pub fn br_multihash_copyimpl(dst: &mut br_multihash_context, src: &br_multihash_context) {
    dst.r#impl = src.r#impl;
}
