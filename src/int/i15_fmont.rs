/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_from_monty` (mirrors `src/int/i15_fmont.c`).

use super::i15_sub::br_i15_sub;
use crate::inner::{MUL15, NOT};

/// Convert a modular integer back from Montgomery representation. m0i is
/// -(1/m0) mod 2^15.
pub fn br_i15_from_monty(x: &mut [u16], m: &[u16], m0i: u16) {
    let len = ((m[0] + 15) >> 4) as usize;
    for _u in 0..len {
        let f = MUL15(x[1] as u32, m0i as u32) & 0x7FFF;
        let mut cc: u32 = 0;
        for v in 0..len {
            let z = x[v + 1] as u32 + MUL15(f, m[v + 1] as u32) + cc;
            cc = z >> 15;
            if v != 0 {
                x[v] = (z & 0x7FFF) as u16;
            }
        }
        x[len] = cc as u16;
    }

    let ctl = NOT(br_i15_sub(x, m, 0));
    br_i15_sub(x, m, ctl);
}
