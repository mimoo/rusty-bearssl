/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_ninv15` (mirrors `src/int/i15_ninv15.c`).

use crate::inner::{MUL15, MUX};

/// Compute -(1/x) mod 2^15. If x is even, then this function returns 0.
pub fn br_i15_ninv15(x: u16) -> u16 {
    let x = x as u32;
    let mut y = 2u32.wrapping_sub(x);
    y = MUL15(y, 2u32.wrapping_sub(MUL15(x, y)));
    y = MUL15(y, 2u32.wrapping_sub(MUL15(x, y)));
    y = MUL15(y, 2u32.wrapping_sub(MUL15(x, y)));
    (MUX(x & 1, y.wrapping_neg(), 0) & 0x7FFF) as u16
}
