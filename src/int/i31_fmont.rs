/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_from_monty` (mirrors `src/int/i31_fmont.c`).

use super::i31_sub::br_i31_sub;
use crate::inner::{MUL31, MUL31_lo, NOT};

/// Convert a modular integer back from Montgomery representation. x[] must be
/// lower than m[] with the same announced bit length. m0i is -(1/m0) mod 2^31.
pub fn br_i31_from_monty(x: &mut [u32], m: &[u32], m0i: u32) {
    let len = ((m[0] + 31) >> 5) as usize;
    for _u in 0..len {
        let f = MUL31_lo(x[1], m0i);
        let mut cc: u64 = 0;
        for v in 0..len {
            let z = x[v + 1] as u64 + MUL31(f, m[v + 1]) + cc;
            cc = z >> 31;
            if v != 0 {
                x[v] = (z as u32) & 0x7FFFFFFF;
            }
        }
        x[len] = cc as u32;
    }

    let ctl = NOT(br_i31_sub(x, m, 0));
    br_i31_sub(x, m, ctl);
}
