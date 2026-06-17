/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_bit_length` (mirrors `src/int/i32_bitlen.c`).

use crate::inner::{BIT_LENGTH, EQ, MUX};

/// Compute the actual bit length of an integer. x points to the first (least
/// significant) value word; xlen is the number of 32-bit words to access.
pub fn br_i32_bit_length(x: &[u32], mut xlen: usize) -> u32 {
    let mut tw: u32 = 0;
    let mut twk: u32 = 0;
    while xlen > 0 {
        xlen -= 1;
        let c = EQ(tw, 0);
        let w = x[xlen];
        tw = MUX(c, w, tw);
        twk = MUX(c, xlen as u32, twk);
    }
    (twk << 5).wrapping_add(BIT_LENGTH(tw))
}
