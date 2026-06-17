/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_iszero` (mirrors `src/int/i31_iszero.c`).

/// Test whether an integer is zero.
pub fn br_i31_iszero(x: &[u32]) -> u32 {
    let mut z: u32 = 0;
    let mut u = ((x[0] + 31) >> 5) as usize;
    while u > 0 {
        z |= x[u];
        u -= 1;
    }
    !(z | z.wrapping_neg()) >> 31
}
