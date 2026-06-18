/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Pseudo-random number generators (`src/rand/`).
//!
//! The C OOP `br_prng_class` vtable is modelled (as elsewhere) with a trait for
//! the per-instance behaviour. Each PRNG context also keeps its `vtable` field.

use crate::hash::br_hash_class;
use crate::symcipher::br_block_ctr_class;

/// Runtime interface of a PRNG (the methods of `br_prng_class`).
pub trait PrngState {
    /// Produce `out.len()` pseudorandom bytes, updating the state.
    fn generate(&mut self, out: &mut [u8]);
    /// Inject additional seed bytes into the entropy pool.
    fn update(&mut self, seed: &[u8]);
}

/// Implementation-specific parameter passed to `br_prng_class::init`.
///
/// In the C source this is a `const void *params` whose meaning depends on the
/// PRNG: for HMAC_DRBG it is a `const br_hash_class *`, for AES/CTR DRBG it is a
/// `const br_block_ctr_class *`. We model that with an enum so the single `init`
/// function pointer type can construct either DRBG.
#[derive(Clone, Copy)]
pub enum PrngParams {
    /// Hash function vtable (HMAC_DRBG).
    Hash(&'static br_hash_class),
    /// Block-cipher CTR vtable (AES/CTR DRBG).
    BlockCtr(&'static br_block_ctr_class),
}

/// PRNG class descriptor (`br_prng_class`).
pub struct br_prng_class {
    pub context_size: usize,
    /// Construct + seed a new PRNG instance. `params` is implementation
    /// specific (see [`PrngParams`]).
    pub init: fn(params: PrngParams, seed: &[u8]) -> Box<dyn PrngState>,
}

mod aesctr_drbg;
mod hmac_drbg;
mod sysrng;

pub use aesctr_drbg::{
    br_aesctr_drbg_context, br_aesctr_drbg_generate, br_aesctr_drbg_init, br_aesctr_drbg_update,
    br_aesctr_drbg_vtable,
};
pub use hmac_drbg::{
    br_hmac_drbg_context, br_hmac_drbg_generate, br_hmac_drbg_init, br_hmac_drbg_update,
    br_hmac_drbg_vtable,
};
pub use sysrng::{br_prng_seeder, br_prng_seeder_system};
