/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Encoded OIDs for the standard hash functions (`src/hash/dig_oid.c`).
//!
//! These OIDs appear in, for instance, the PKCS#1 v1.5 padding for RSA
//! signatures.

use super::*;

static md5_OID: [u8; 8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05];
static sha1_OID: [u8; 5] = [0x2B, 0x0E, 0x03, 0x02, 0x1A];
static sha224_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
static sha256_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
static sha384_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
static sha512_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// see inner.h
///
/// Returns the DER-encoded OID for the given digest id, or `None` for an
/// unknown / OID-less digest (matching the C `NULL` return with `*len = 0`).
pub fn br_digest_OID(digest_id: i32) -> Option<&'static [u8]> {
    match digest_id as u32 {
        br_md5_ID => Some(&md5_OID),
        br_sha1_ID => Some(&sha1_OID),
        br_sha224_ID => Some(&sha224_OID),
        br_sha256_ID => Some(&sha256_OID),
        br_sha384_ID => Some(&sha384_OID),
        br_sha512_ID => Some(&sha512_OID),
        _ => None,
    }
}
