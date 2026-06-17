/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Authenticated encryption with associated data (`src/aead/`): GCM, CCM, EAX.
//!
//! The C OOP `br_aead_class` vtable is modelled with the [`Aead`] trait.

/// Runtime interface of an AEAD computation (the methods of `br_aead_class`).
pub trait Aead {
    /// Authentication tag size, in bytes.
    fn tag_size(&self) -> usize;
    /// Reset for a new run with nonce `iv`.
    fn reset(&mut self, iv: &[u8]);
    /// Inject additional authenticated data (before `flip`).
    fn aad_inject(&mut self, data: &[u8]);
    /// Finish AAD injection; must be called before `run`.
    fn flip(&mut self);
    /// Encrypt (`encrypt = true`) or decrypt `data` in place.
    fn run(&mut self, encrypt: bool, data: &mut [u8]);
    /// Compute the full authentication tag.
    fn get_tag(&mut self, tag: &mut [u8]);
    /// Compute a truncated authentication tag (`len` bytes).
    fn get_tag_trunc(&mut self, tag: &mut [u8], len: usize);
    /// Constant-time check of a full tag; returns 1 on match, 0 otherwise.
    fn check_tag(&mut self, tag: &[u8]) -> u32;
    /// Constant-time check of a truncated tag.
    fn check_tag_trunc(&mut self, tag: &[u8], len: usize) -> u32;
}

mod ccm;
mod gcm;

pub use ccm::{
    br_ccm_aad_inject, br_ccm_check_tag, br_ccm_context, br_ccm_flip, br_ccm_get_tag, br_ccm_init,
    br_ccm_reset, br_ccm_run,
};
pub use gcm::{
    br_gcm_aad_inject, br_gcm_check_tag, br_gcm_check_tag_trunc, br_gcm_context, br_gcm_flip,
    br_gcm_get_tag, br_gcm_get_tag_trunc, br_gcm_init, br_gcm_reset, br_gcm_run,
};

// CCM and EAX (ccm.c, eax.c) build on the CTR+CBC-MAC block-cipher class;
// ported in a later pass once that class has an AES implementation.
