/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Digest output size lookup (`src/hash/dig_size.c`).

use super::*;

/// see inner.h
pub fn br_digest_size_by_ID(digest_id: i32) -> usize {
    match digest_id as u32 {
        br_md5sha1_ID => br_md5_SIZE + br_sha1_SIZE,
        br_md5_ID => br_md5_SIZE,
        br_sha1_ID => br_sha1_SIZE,
        br_sha224_ID => br_sha224_SIZE,
        br_sha256_ID => br_sha256_SIZE,
        br_sha384_ID => br_sha384_SIZE,
        br_sha512_ID => br_sha512_SIZE,
        _ => 0,
    }
}

/// Output size of a hash function, read from its descriptor (inner.h
/// `br_digest_size`).
pub fn br_digest_size(dig: &br_hash_class) -> usize {
    dig.out_size()
}
