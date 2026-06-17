/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_mulacc` (mirrors `src/int/i31_mulacc.c`).

use crate::inner::MUL31;

/// Compute d+a*b, result in d. The initial announced bit length of d[] must
/// match that of a[]. d[] must be large enough for the full result plus an
/// extra word, and disjoint from a and b.
pub fn br_i31_mulacc(d: &mut [u32], a: &[u32], b: &[u32]) {
    let alen = ((a[0] + 31) >> 5) as usize;
    let blen = ((b[0] + 31) >> 5) as usize;

    let dl = (a[0] & 31) + (b[0] & 31);
    let dh = (a[0] >> 5) + (b[0] >> 5);
    d[0] = (dh << 5)
        .wrapping_add(dl)
        .wrapping_add(!(dl.wrapping_sub(31)) >> 31);

    for u in 0..blen {
        let f = b[1 + u];
        let mut cc: u64 = 0;
        for v in 0..alen {
            let z = d[1 + u + v] as u64 + MUL31(f, a[1 + v]) + cc;
            cc = z >> 31;
            d[1 + u + v] = (z as u32) & 0x7FFFFFFF;
        }
        d[1 + u + alen] = cc as u32;
    }
}
