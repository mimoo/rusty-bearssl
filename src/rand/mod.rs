/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Pseudo-random number generators (`src/rand/`).
//!
//! The C OOP `br_prng_class` vtable is modelled (as elsewhere) with a trait for
//! the per-instance behaviour. Each PRNG context also keeps its `vtable` field.

use crate::hash::br_hash_class;

/// Runtime interface of a PRNG (the methods of `br_prng_class`).
pub trait PrngState {
    /// Produce `out.len()` pseudorandom bytes, updating the state.
    fn generate(&mut self, out: &mut [u8]);
    /// Inject additional seed bytes into the entropy pool.
    fn update(&mut self, seed: &[u8]);
}

/// PRNG class descriptor (`br_prng_class`).
pub struct br_prng_class {
    pub context_size: usize,
    /// Construct + seed a new PRNG instance. `params` is implementation
    /// specific (for HMAC_DRBG it is the hash function vtable).
    pub init: fn(params: &'static br_hash_class, seed: &[u8]) -> Box<dyn PrngState>,
}

mod hmac_drbg;

pub use hmac_drbg::{
    br_hmac_drbg_context, br_hmac_drbg_generate, br_hmac_drbg_init, br_hmac_drbg_update,
    br_hmac_drbg_vtable,
};
