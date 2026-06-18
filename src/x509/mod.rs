/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! X.509 certificate handling (`src/x509/`).
//!
//! Mirrors BearSSL's `src/x509/` directory. The bulk of these engines is emitted
//! by BearSSL's "T0" compiler: a stack-based bytecode interpreter plus a code
//! block, data block and address table. The shared interpreter primitives live
//! in [`t0`]; each engine ports its own opcode dispatch and embeds the verbatim
//! generated code/data blocks (see the per-file dump of `offsetof`-baked offset
//! constants).
//!
//! ## Ported engines
//!
//! * [`x509_decoder`] — single-certificate decoder: extracts the subject DN
//!   (via callback) and the public key. **Done.**
//! * [`skey_decoder`] — private key decoder (RSA / EC, raw or PKCS#8). **Done.**
//! * [`x509_knownkey`] — trivial engine returning a fixed, externally known key.
//!   **Done.**
//! * [`x509_minimal`] — full chain validation against trust anchors, with DN
//!   matching, signature verification, validity dates, Basic Constraints, Key
//!   Usage, and Subject Alt Name / Common Name server-name matching. **Done.**
//!
//! ## Deviations from C
//!
//! * The C engines treat their context struct as a flat byte buffer addressed by
//!   `offsetof`. Raw pointer arithmetic over a `repr(C)` struct is not expressed
//!   in safe Rust, so each engine keeps a flat `mem: [u8; sizeof(ctx)]` buffer,
//!   uses the genuine upstream `offsetof` values (so the generated code block is
//!   byte-identical), and routes byte-addressed opcodes through small accessors.
//!   Fields that the T0 code never byte-addresses (the VM stacks, the output
//!   `pkey`, callback pointers) are modelled as ordinary Rust fields.
//! * [`br_x509_pkey`] is an owned enum rather than the C tagged union; decoded
//!   key bytes are copied out of the context's key buffer so the returned key is
//!   self-contained.
//! * The `br_x509_class` vtable's `start_chain`/`start_cert`/`append`/`end_cert`/
//!   `end_chain`/`get_pkey` flow is preserved as a Rust trait, [`X509Engine`].

pub mod t0;

pub use t0::{
    BR_KEYTYPE_EC, BR_KEYTYPE_KEYX, BR_KEYTYPE_RSA, BR_KEYTYPE_SIGN, BR_X509_BUFSIZE_KEY,
    BR_X509_BUFSIZE_SIG,
};
// Re-export the X.509 error codes.
pub use t0::{
    BR_ERR_X509_BAD_BOOLEAN, BR_ERR_X509_BAD_DN, BR_ERR_X509_BAD_SERVER_NAME,
    BR_ERR_X509_BAD_SIGNATURE, BR_ERR_X509_BAD_TAG_CLASS, BR_ERR_X509_BAD_TAG_VALUE,
    BR_ERR_X509_BAD_TIME, BR_ERR_X509_CRITICAL_EXTENSION, BR_ERR_X509_DN_MISMATCH,
    BR_ERR_X509_EMPTY_CHAIN, BR_ERR_X509_EXPIRED, BR_ERR_X509_EXTRA_ELEMENT,
    BR_ERR_X509_FORBIDDEN_KEY_USAGE, BR_ERR_X509_INDEFINITE_LENGTH, BR_ERR_X509_INNER_TRUNC,
    BR_ERR_X509_INVALID_VALUE, BR_ERR_X509_LIMIT_EXCEEDED, BR_ERR_X509_NOT_CA,
    BR_ERR_X509_NOT_CONSTRUCTED, BR_ERR_X509_NOT_PRIMITIVE, BR_ERR_X509_NOT_TRUSTED,
    BR_ERR_X509_OK, BR_ERR_X509_OVERFLOW, BR_ERR_X509_PARTIAL_BYTE, BR_ERR_X509_TIME_UNKNOWN,
    BR_ERR_X509_TRUNCATED, BR_ERR_X509_UNEXPECTED, BR_ERR_X509_UNSUPPORTED,
    BR_ERR_X509_WEAK_PUBLIC_KEY, BR_ERR_X509_WRONG_KEY_TYPE,
};

/// Trust anchor flag: CA (`BR_X509_TA_CA`).
pub const BR_X509_TA_CA: u32 = 0x0001;

/// Aggregate public key (`br_x509_pkey`).
///
/// In C this is a `key_type` tag plus a union of `br_rsa_public_key` /
/// `br_ec_public_key`. Here it is an owned enum: the key bytes are copied out of
/// the decoder's working buffer so the value is self-contained. `key_type()`
/// recovers the C tag value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum br_x509_pkey {
    /// No key decoded yet.
    None,
    /// RSA public key: modulus `n` and public exponent `e` (big-endian).
    RSA { n: Vec<u8>, e: Vec<u8> },
    /// EC public key: curve id and encoded point `q`.
    EC { curve: i32, q: Vec<u8> },
}

impl br_x509_pkey {
    /// The C `key_type` tag (`BR_KEYTYPE_RSA`, `BR_KEYTYPE_EC`, or 0).
    pub fn key_type(&self) -> u8 {
        match self {
            br_x509_pkey::None => 0,
            br_x509_pkey::RSA { .. } => BR_KEYTYPE_RSA,
            br_x509_pkey::EC { .. } => BR_KEYTYPE_EC,
        }
    }
}

/// Owned private key (decoded by [`skey_decoder`]).
///
/// Mirrors the C `br_skey_decoder_context.key` union plus the side buffer it
/// points into; the element bytes are owned here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum br_skey {
    /// No key decoded yet.
    None,
    /// RSA private key (CRT form): `n_bitlen` plus `p`, `q`, `dp`, `dq`, `iq`.
    RSA {
        n_bitlen: u32,
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        iq: Vec<u8>,
    },
    /// EC private key: curve id and scalar `x` (big-endian).
    EC { curve: i32, x: Vec<u8> },
}

impl br_skey {
    /// The C `key_type` tag (`BR_KEYTYPE_RSA`, `BR_KEYTYPE_EC`, or 0).
    pub fn key_type(&self) -> u8 {
        match self {
            br_skey::None => 0,
            br_skey::RSA { .. } => BR_KEYTYPE_RSA,
            br_skey::EC { .. } => BR_KEYTYPE_EC,
        }
    }
}

/// Distinguished Name (`br_x500_name`): a DER-encoded X.500 name.
#[derive(Clone, Copy)]
pub struct br_x500_name<'a> {
    pub data: &'a [u8],
}

/// Trust anchor (`br_x509_trust_anchor`): a DN, flags, and a public key.
pub struct br_x509_trust_anchor<'a> {
    pub dn: &'a [u8],
    pub flags: u32,
    pub pkey: br_x509_pkey,
}

/// Name element to gather (`br_name_element`): an OID selector, a destination
/// buffer, and a decoding status.
pub struct br_name_element<'a> {
    /// OID selector (length-prefixed for DN elements; `0`-prefixed for SAN).
    pub oid: &'a [u8],
    /// Destination buffer (filled with a NUL-terminated string when matched).
    pub buf: &'a mut [u8],
    /// Decoding status: 0 = not found, 1 = found, -1 = error.
    pub status: i32,
}

/// The X.509 engine interface (`br_x509_class` vtable).
///
/// Methods are invoked in order: `start_chain`, then per certificate
/// `start_cert` / `append`* / `end_cert`, then `end_chain`, then `get_pkey`.
pub trait X509Engine {
    fn start_chain(&mut self, server_name: Option<&str>);
    fn start_cert(&mut self, length: u32);
    fn append(&mut self, buf: &[u8]);
    fn end_cert(&mut self);
    fn end_chain(&mut self) -> u32;
    fn get_pkey(&self, usages: Option<&mut u32>) -> Option<&br_x509_pkey>;
}

mod x509_decoder;
mod x509_knownkey;
mod x509_minimal;
mod skey_decoder;

pub mod asn1enc;
mod encode_ec_pk8der;
mod encode_ec_rawder;
mod encode_rsa_pk8der;
mod encode_rsa_rawder;

pub use asn1enc::{
    br_asn1_encode_length, br_asn1_encode_uint, br_asn1_uint, br_asn1_uint_prepare, len_of_len,
};
pub use encode_ec_pk8der::br_encode_ec_pkcs8_der;
pub use encode_ec_rawder::{
    br_encode_ec_raw_der, br_encode_ec_raw_der_inner, br_get_curve_OID,
};
pub use encode_rsa_pk8der::br_encode_rsa_pkcs8_der;
pub use encode_rsa_rawder::br_encode_rsa_raw_der;

pub use skey_decoder::{
    br_skey_decoder_context, br_skey_decoder_init, br_skey_decoder_push,
};
pub use x509_decoder::{
    br_x509_decoder_context, br_x509_decoder_init, br_x509_decoder_push,
};
pub use x509_knownkey::{
    br_x509_knownkey_context, br_x509_knownkey_init_ec, br_x509_knownkey_init_rsa,
};
pub use x509_minimal::{
    br_x509_minimal_context, br_x509_minimal_init, br_x509_minimal_init_full,
};
