/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! MGF1 mask generation function (`src/hash/mgf1.c`), used by RSA OAEP/PSS.

use super::dig_size::br_digest_size;
use super::*;
use crate::inner::br_enc32be;

/// see inner.h
///
/// XORs into `data` (the first `len` bytes) the MGF1 mask derived from `seed`
/// using hash function `dig`.
pub fn br_mgf1_xor(data: &mut [u8], len: usize, dig: &br_hash_class, seed: &[u8]) {
    let hlen = br_digest_size(dig);
    let mut u = 0usize;
    let mut c: u32 = 0;
    while u < len {
        let mut hc = (dig.new)();
        let mut tmp = [0u8; 64];
        hc.update(seed);
        br_enc32be(&mut tmp, c);
        hc.update(&tmp[..4]);
        hc.out(&mut tmp);
        let mut v = 0usize;
        while v < hlen {
            if u + v >= len {
                break;
            }
            data[u + v] ^= tmp[v];
            v += 1;
        }
        u += hlen;
        c += 1;
    }
}
