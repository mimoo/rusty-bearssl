/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_modpow` (mirrors `src/int/i15_modpow.c`).

use super::ccopy_words16;
use super::i15_montmul::br_i15_montymul;
use super::i15_tmont::br_i15_to_monty;
use super::{br_i15_zero, i15_words};

/// Compute a modular exponentiation. x[] must be an integer modulo m[]. m[]
/// must be odd. m0i is -(1/m0) mod 2^15. t1 and t2 are temporaries the size of
/// m[].
pub fn br_i15_modpow(
    x: &mut [u16],
    e: &[u8],
    elen: usize,
    m: &[u16],
    m0i: u16,
    t1: &mut [u16],
    t2: &mut [u16],
) {
    let mwords = i15_words(m[0]);
    t1[..mwords].copy_from_slice(&x[..mwords]);
    br_i15_to_monty(t1, m);
    br_i15_zero(x, m[0]);
    x[1] = 1;
    for k in 0..((elen as u32) << 3) {
        let ctl = (e[elen - 1 - (k >> 3) as usize] >> (k & 7)) & 1;
        br_i15_montymul(t2, x, t1, m, m0i);
        ccopy_words16(ctl as u32, x, t2, mwords);
        br_i15_montymul(t2, t1, t1, m, m0i);
        t1[..mwords].copy_from_slice(&t2[..mwords]);
    }
}
