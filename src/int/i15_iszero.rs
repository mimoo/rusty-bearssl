/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_iszero` (mirrors `src/int/i15_iszero.c`).

/// Test whether an integer is zero.
pub fn br_i15_iszero(x: &[u16]) -> u32 {
    let mut z: u32 = 0;
    let mut u = ((x[0] + 15) >> 4) as usize;
    while u > 0 {
        z |= x[u] as u32;
        u -= 1;
    }
    !(z | z.wrapping_neg()) >> 31
}
