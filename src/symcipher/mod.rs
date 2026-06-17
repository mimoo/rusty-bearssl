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

mod aes_common;
mod aes_ct;
mod aes_ct_cbcdec;
mod aes_ct_cbcenc;
mod aes_ct_ctr;
mod aes_ct_ctrcbc;
mod aes_ct_dec;
mod aes_ct_enc;
mod chacha20_ct;
mod des_ct;
mod des_ct_cbcdec;
mod des_ct_cbcenc;
mod des_support;
mod poly1305_ctmul;

pub use aes_common::{br_aes_keysched, br_aes_S};
pub use aes_ct::{
    br_aes_ct_bitslice_Sbox, br_aes_ct_keysched, br_aes_ct_ortho, br_aes_ct_skey_expand,
};
pub use aes_ct_cbcdec::{
    br_aes_ct_cbcdec_init, br_aes_ct_cbcdec_keys, br_aes_ct_cbcdec_run, br_aes_ct_cbcdec_vtable,
};
pub use aes_ct_cbcenc::{
    br_aes_ct_cbcenc_init, br_aes_ct_cbcenc_keys, br_aes_ct_cbcenc_run, br_aes_ct_cbcenc_vtable,
};
pub use aes_ct_ctr::{
    br_aes_ct_ctr_init, br_aes_ct_ctr_keys, br_aes_ct_ctr_run, br_aes_ct_ctr_vtable,
};
pub use aes_ct_ctrcbc::{
    br_aes_ct_ctrcbc_ctr, br_aes_ct_ctrcbc_decrypt, br_aes_ct_ctrcbc_encrypt,
    br_aes_ct_ctrcbc_init, br_aes_ct_ctrcbc_keys, br_aes_ct_ctrcbc_mac, br_aes_ct_ctrcbc_vtable,
};
pub use aes_ct_dec::{br_aes_ct_bitslice_decrypt, br_aes_ct_bitslice_invSbox};
pub use aes_ct_enc::br_aes_ct_bitslice_encrypt;
pub use chacha20_ct::{br_chacha20_ct_run, br_chacha20_run};
pub use des_ct::{br_des_ct_keysched, br_des_ct_process_block, br_des_ct_skey_expand};
pub use des_ct_cbcdec::{
    br_des_ct_cbcdec_init, br_des_ct_cbcdec_keys, br_des_ct_cbcdec_run, br_des_ct_cbcdec_vtable,
};
pub use des_ct_cbcenc::{
    br_des_ct_cbcenc_init, br_des_ct_cbcenc_keys, br_des_ct_cbcenc_run, br_des_ct_cbcenc_vtable,
};
pub use des_support::{br_des_do_IP, br_des_do_invIP, br_des_keysched_unit, br_des_rev_skey};
pub use poly1305_ctmul::br_poly1305_ctmul_run;
