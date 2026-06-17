/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_mulacc` (mirrors `src/int/i32_mulacc.c`).

use crate::inner::MUL;

/// Compute d+a*b, result in d.
pub fn br_i32_mulacc(d: &mut [u32], a: &[u32], b: &[u32]) {
    let alen = ((a[0] + 31) >> 5) as usize;
    let blen = ((b[0] + 31) >> 5) as usize;
    d[0] = a[0].wrapping_add(b[0]);
    for u in 0..blen {
        let f = b[1 + u];
        let mut cc: u64 = 0;
        for v in 0..alen {
            let z = d[1 + u + v] as u64 + MUL(f, a[1 + v]) + cc;
            cc = z >> 32;
            d[1 + u + v] = z as u32;
        }
        d[1 + u + alen] = cc as u32;
    }
}
