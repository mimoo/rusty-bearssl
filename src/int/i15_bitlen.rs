/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_bit_length` (mirrors `src/int/i15_bitlen.c`).

use crate::inner::{BIT_LENGTH, EQ, MUX};

/// Compute the ENCODED actual bit length of an integer (15-bit words).
pub fn br_i15_bit_length(x: &[u16], mut xlen: usize) -> u32 {
    let mut tw: u32 = 0;
    let mut twk: u32 = 0;
    while xlen > 0 {
        xlen -= 1;
        let c = EQ(tw, 0);
        let w = x[xlen] as u32;
        tw = MUX(c, w, tw);
        twk = MUX(c, xlen as u32, twk);
    }
    (twk << 4).wrapping_add(BIT_LENGTH(tw))
}
