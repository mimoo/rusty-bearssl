/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_to_monty` (mirrors `src/int/i32_tmont.c`).

use super::i32_muladd::br_i32_muladd_small;

/// Convert a modular integer to Montgomery representation.
pub fn br_i32_to_monty(x: &mut [u32], m: &[u32]) {
    let mut k = (m[0] + 31) >> 5;
    while k > 0 {
        br_i32_muladd_small(x, 0, m);
        k -= 1;
    }
}
