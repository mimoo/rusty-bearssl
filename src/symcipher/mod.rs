/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Symmetric ciphers (`src/symcipher/`): AES (constant-time), DES, ChaCha20,
//! Poly1305, and the block-cipher mode classes (CBC enc/dec, CTR, CTR+CBC-MAC).
//!
//! The C OOP block-cipher classes (`br_block_cbcenc_class`, ...) are modelled
//! here exactly as the hash module models `br_hash_class`: a descriptor struct
//! carrying metadata plus a constructor, paired with a trait object for the
//! per-key runtime behaviour. The algorithms themselves are ported verbatim.

// ---- block-cipher mode traits (runtime behaviour) ---------------------------

/// CBC encryption over a configured key.
pub trait CbcEnc {
    /// Encrypt `data` in place (length a multiple of block size); `iv` is
    /// updated with the last ciphertext block.
    fn run(&self, iv: &mut [u8], data: &mut [u8]);
}

/// CBC decryption over a configured key.
pub trait CbcDec {
    /// Decrypt `data` in place (length a multiple of block size); `iv` is
    /// updated with the last ciphertext block.
    fn run(&self, iv: &mut [u8], data: &mut [u8]);
}

/// CTR encryption/decryption over a configured key.
pub trait Ctr {
    /// Process `data` in place using counter `cc`; returns the new counter.
    fn run(&self, iv: &[u8], cc: u32, data: &mut [u8]) -> u32;
}

/// Combined CTR encryption with CBC-MAC over a configured key.
pub trait CtrCbc {
    fn encrypt(&self, ctr: &mut [u8], cbcmac: &mut [u8], data: &mut [u8]);
    fn decrypt(&self, ctr: &mut [u8], cbcmac: &mut [u8], data: &mut [u8]);
    fn ctr(&self, ctr: &mut [u8], data: &mut [u8]);
    fn mac(&self, cbcmac: &mut [u8], data: &[u8]);
}

// ---- block-cipher class descriptors (vtables) -------------------------------

/// Class type for CBC encryption implementations (`br_block_cbcenc_class`).
pub struct br_block_cbcenc_class {
    pub context_size: usize,
    pub block_size: u32,
    pub log_block_size: u32,
    /// Initialise subkeys from `key` and return the running implementation.
    pub init: fn(key: &[u8]) -> Box<dyn CbcEnc>,
}

/// Class type for CBC decryption implementations (`br_block_cbcdec_class`).
pub struct br_block_cbcdec_class {
    pub context_size: usize,
    pub block_size: u32,
    pub log_block_size: u32,
    pub init: fn(key: &[u8]) -> Box<dyn CbcDec>,
}

/// Class type for CTR implementations (`br_block_ctr_class`).
pub struct br_block_ctr_class {
    pub context_size: usize,
    pub block_size: u32,
    pub log_block_size: u32,
    pub init: fn(key: &[u8]) -> Box<dyn Ctr>,
}

/// Class type for combined CTR + CBC-MAC implementations (`br_block_ctrcbc_class`).
pub struct br_block_ctrcbc_class {
    pub context_size: usize,
    pub block_size: u32,
    pub log_block_size: u32,
    pub init: fn(key: &[u8]) -> Box<dyn CtrCbc>,
}

pub const br_aes_big_BLOCK_SIZE: usize = 16;
pub const br_aes_small_BLOCK_SIZE: usize = 16;
pub const br_aes_ct_BLOCK_SIZE: usize = 16;
pub const br_aes_ct64_BLOCK_SIZE: usize = 16;
pub const br_des_tab_BLOCK_SIZE: usize = 8;
pub const br_des_ct_BLOCK_SIZE: usize = 8;

// Algorithm implementations are filled in per-file (aes_ct*, chacha20*, des*,
// poly1305*) and declared here as they are ported.
