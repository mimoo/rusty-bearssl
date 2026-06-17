/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_modpow` (mirrors `src/int/i31_modpow.c`).

use super::ccopy_words;
use super::i31_montmul::br_i31_montymul;
use super::i31_tmont::br_i31_to_monty;
use super::{br_i31_zero, i31_words};

/// Compute a modular exponentiation. x[] must be an integer modulo m[] (same
/// announced bit length, lower value). m[] must be odd. m0i is -(1/m0) mod
/// 2^31. t1 and t2 are temporaries large enough to hold an integer the size of
/// m[].
pub fn br_i31_modpow(
    x: &mut [u32],
    e: &[u8],
    elen: usize,
    m: &[u32],
    m0i: u32,
    t1: &mut [u32],
    t2: &mut [u32],
) {
    // Number of words occupied by an m-sized value, including the header.
    let mwords = i31_words(m[0]);
    t1[..mwords].copy_from_slice(&x[..mwords]);
    br_i31_to_monty(t1, m);
    br_i31_zero(x, m[0]);
    x[1] = 1;
    for k in 0..((elen as u32) << 3) {
        let ctl = (e[elen - 1 - (k >> 3) as usize] >> (k & 7)) & 1;
        br_i31_montymul(t2, x, t1, m, m0i);
        ccopy_words(ctl as u32, x, t2, mwords);
        br_i31_montymul(t2, t1, t1, m, m0i);
        t1[..mwords].copy_from_slice(&t2[..mwords]);
    }
}
