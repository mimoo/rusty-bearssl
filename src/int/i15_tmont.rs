/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_to_monty` (mirrors `src/int/i15_tmont.c`).

use super::i15_muladd::br_i15_muladd_small;

/// Convert a modular integer to Montgomery representation.
pub fn br_i15_to_monty(x: &mut [u16], m: &[u16]) {
    let mut k = (m[0] + 15) >> 4;
    while k > 0 {
        br_i15_muladd_small(x, 0, m);
        k -= 1;
    }
}
