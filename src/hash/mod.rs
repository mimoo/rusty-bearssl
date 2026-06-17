/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Hash functions (`src/hash/`).
//!
//! Mirrors BearSSL's `src/hash/` directory. Each Merkle–Damgård hash keeps its
//! exact round function and update/finalize logic from the C source. The C OOP
//! vtable (`br_hash_class`) is modelled here as a descriptor struct plus a
//! [`HashState`] trait object for dynamic dispatch; each context still carries a
//! `vtable: &'static br_hash_class` field exactly as the C contexts do, so the
//! identity/metadata distinctions (e.g. SHA-224 vs SHA-256) are preserved.

// ---- descriptor word (BR_HASHDESC_*) layout, from inc/bearssl_hash.h --------

pub const BR_HASHDESC_ID_OFF: u32 = 0;
pub const BR_HASHDESC_ID_MASK: u32 = 0xFF;
pub const BR_HASHDESC_OUT_OFF: u32 = 8;
pub const BR_HASHDESC_OUT_MASK: u32 = 0x7F;
pub const BR_HASHDESC_STATE_OFF: u32 = 15;
pub const BR_HASHDESC_STATE_MASK: u32 = 0xFF;
pub const BR_HASHDESC_LBLEN_OFF: u32 = 23;
pub const BR_HASHDESC_LBLEN_MASK: u32 = 0x0F;
pub const BR_HASHDESC_MD_PADDING: u32 = 1 << 28;
pub const BR_HASHDESC_MD_PADDING_128: u32 = 1 << 29;
pub const BR_HASHDESC_MD_PADDING_BE: u32 = 1 << 30;

pub const fn BR_HASHDESC_ID(id: u32) -> u32 {
    id << BR_HASHDESC_ID_OFF
}
pub const fn BR_HASHDESC_OUT(size: u32) -> u32 {
    size << BR_HASHDESC_OUT_OFF
}
pub const fn BR_HASHDESC_STATE(size: u32) -> u32 {
    size << BR_HASHDESC_STATE_OFF
}
pub const fn BR_HASHDESC_LBLEN(ls: u32) -> u32 {
    ls << BR_HASHDESC_LBLEN_OFF
}

// ---- symbolic identifiers and output sizes (inc/bearssl_hash.h) -------------

pub const br_md5sha1_ID: u32 = 0;
pub const br_md5sha1_SIZE: usize = 36;
pub const br_md5_ID: u32 = 1;
pub const br_md5_SIZE: usize = 16;
pub const br_sha1_ID: u32 = 2;
pub const br_sha1_SIZE: usize = 20;
pub const br_sha224_ID: u32 = 3;
pub const br_sha224_SIZE: usize = 28;
pub const br_sha256_ID: u32 = 4;
pub const br_sha256_SIZE: usize = 32;
pub const br_sha384_ID: u32 = 5;
pub const br_sha384_SIZE: usize = 48;
pub const br_sha512_ID: u32 = 6;
pub const br_sha512_SIZE: usize = 64;

/// The descriptor / vtable for a hash function. Equivalent to C's
/// `br_hash_class`: it carries the descriptor word plus a constructor that
/// yields a fresh, initialised dynamic context.
pub struct br_hash_class {
    /// Size of the matching C context (informational; Rust allocates via `new`).
    pub context_size: usize,
    /// Descriptor word; decode with the `BR_HASHDESC_*` helpers.
    pub desc: u32,
    /// Create a new, initialised context for this hash function.
    pub new: fn() -> Box<dyn HashState>,
}

impl br_hash_class {
    /// Hash function symbolic id (`ID` field of `desc`).
    pub fn id(&self) -> u32 {
        (self.desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK
    }
    /// Output size in bytes (`OUT` field of `desc`).
    pub fn out_size(&self) -> usize {
        ((self.desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK) as usize
    }
    /// Running state size in bytes (`STATE` field of `desc`).
    pub fn state_size(&self) -> usize {
        ((self.desc >> BR_HASHDESC_STATE_OFF) & BR_HASHDESC_STATE_MASK) as usize
    }
}

/// Dynamic hash-context interface (the methods of `br_hash_class`, bound to a
/// concrete running context). Implemented by every hash context type.
pub trait HashState: HashStateClone {
    /// The descriptor (vtable) this context belongs to.
    fn vtable(&self) -> &'static br_hash_class;
    /// Inject `data` into the running computation.
    fn update(&mut self, data: &[u8]);
    /// Write the hash output (does not modify the context).
    fn out(&self, dst: &mut [u8]);
    /// Save the running state into `dst`; returns the injected byte length.
    fn state(&self, dst: &mut [u8]) -> u64;
    /// Replace the running state.
    fn set_state(&mut self, stb: &[u8], count: u64);
}

/// Object-safe clone support for `Box<dyn HashState>` (handshake hashes need to
/// snapshot a running computation, matching the C contexts' copy semantics).
pub trait HashStateClone {
    fn clone_box(&self) -> Box<dyn HashState>;
}

impl<T: 'static + HashState + Clone> HashStateClone for T {
    fn clone_box(&self) -> Box<dyn HashState> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn HashState> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// GHASH implementation function type (`br_ghash` in inc/bearssl_hash.h):
/// updates the 16-byte `y` with key `h` over `data` (zero-padded to 16).
pub type br_ghash = fn(y: &mut [u8], h: &[u8], data: &[u8]);

mod dig_oid;
mod dig_size;
mod ghash_ctmul;
mod md5;
mod md5sha1;
mod mgf1;
mod multihash;
mod sha1;
mod sha2big;
mod sha2small;

pub use dig_oid::br_digest_OID;
pub use dig_size::{br_digest_size, br_digest_size_by_ID};
pub use ghash_ctmul::br_ghash_ctmul;
pub use md5sha1::{
    br_md5sha1_context, br_md5sha1_init, br_md5sha1_out, br_md5sha1_set_state, br_md5sha1_state,
    br_md5sha1_update, br_md5sha1_vtable,
};
pub use mgf1::br_mgf1_xor;
pub use multihash::{
    br_multihash_context, br_multihash_copyimpl, br_multihash_getimpl, br_multihash_init,
    br_multihash_out, br_multihash_setimpl, br_multihash_update, br_multihash_zero,
};

pub use md5::{
    br_md5_context, br_md5_init, br_md5_out, br_md5_round, br_md5_set_state, br_md5_state,
    br_md5_update, br_md5_vtable, br_md5_IV,
};
pub use sha1::{
    br_sha1_context, br_sha1_init, br_sha1_out, br_sha1_round, br_sha1_set_state, br_sha1_state,
    br_sha1_update, br_sha1_vtable, br_sha1_IV,
};
pub use sha2big::{
    br_sha384_context, br_sha384_init, br_sha384_out, br_sha384_state, br_sha384_vtable,
    br_sha512_IV, br_sha512_context, br_sha512_init, br_sha512_out, br_sha512_round,
    br_sha512_set_state, br_sha512_state, br_sha512_update, br_sha512_vtable, br_sha384_IV,
};
pub use sha2small::{
    br_sha224_context, br_sha224_init, br_sha224_out, br_sha224_state, br_sha224_vtable,
    br_sha256_IV, br_sha256_context, br_sha256_init, br_sha256_out, br_sha256_round,
    br_sha256_set_state, br_sha256_state, br_sha256_update, br_sha256_vtable, br_sha224_IV,
};
