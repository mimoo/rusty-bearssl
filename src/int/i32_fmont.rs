/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_from_monty` (mirrors `src/int/i32_fmont.c`).

use super::i32_sub::br_i32_sub;
use crate::inner::{MUL, NOT};

/// Convert a modular integer back from Montgomery representation. m0i is
/// -(1/m0) mod 2^32.
pub fn br_i32_from_monty(x: &mut [u32], m: &[u32], m0i: u32) {
    let len = ((m[0] + 31) >> 5) as usize;
    for _u in 0..len {
        let f = x[1].wrapping_mul(m0i);
        let mut cc: u64 = 0;
        for v in 0..len {
            let z = x[v + 1] as u64 + MUL(f, m[v + 1]) + cc;
            cc = z >> 32;
            if v != 0 {
                x[v] = z as u32;
            }
        }
        x[len] = cc as u32;
    }

    let ctl = NOT(br_i32_sub(x, m, 0));
    br_i32_sub(x, m, ctl);
}
