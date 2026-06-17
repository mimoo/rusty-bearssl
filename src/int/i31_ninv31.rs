/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_ninv31` (mirrors `src/int/i31_ninv31.c`).

use crate::inner::MUX;

/// Compute -(1/x) mod 2^31. If x is even, then this function returns 0.
pub fn br_i31_ninv31(x: u32) -> u32 {
    let mut y = 2u32.wrapping_sub(x);
    y = y.wrapping_mul(2u32.wrapping_sub(y.wrapping_mul(x)));
    y = y.wrapping_mul(2u32.wrapping_sub(y.wrapping_mul(x)));
    y = y.wrapping_mul(2u32.wrapping_sub(y.wrapping_mul(x)));
    y = y.wrapping_mul(2u32.wrapping_sub(y.wrapping_mul(x)));
    MUX(x & 1, y.wrapping_neg(), 0) & 0x7FFFFFFF
}
