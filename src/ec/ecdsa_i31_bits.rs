/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `bits2int` for ECDSA over i31 integers (`src/ec/ecdsa_i31_bits.c`).

use crate::int::{br_i31_decode, br_i31_rshift, br_i31_zero};

/// see inner.h
///
/// Decode some bytes as an i31 integer, with truncation (the `bits2int`
/// operation of RFC 6979). `ebitlen` is the target ENCODED bit length.
pub fn br_ecdsa_i31_bits2int(x: &mut [u32], src: &[u8], mut len: usize, ebitlen: u32) {
    let bitlen = ebitlen - (ebitlen >> 5);
    let hbitlen = (len as u32) << 3;
    let sc: i32;
    if hbitlen > bitlen {
        len = ((bitlen + 7) >> 3) as usize;
        sc = ((hbitlen - bitlen) & 7) as i32;
    } else {
        sc = 0;
    }
    br_i31_zero(x, ebitlen);
    br_i31_decode(x, &src[..len], len);
    br_i31_rshift(x, sc);
    x[0] = ebitlen;
}
