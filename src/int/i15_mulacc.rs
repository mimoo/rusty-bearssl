/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_mulacc` (mirrors `src/int/i15_mulacc.c`).

use crate::inner::MUL15;

/// Compute d+a*b, result in d.
pub fn br_i15_mulacc(d: &mut [u16], a: &[u16], b: &[u16]) {
    let alen = ((a[0] + 15) >> 4) as usize;
    let blen = ((b[0] + 15) >> 4) as usize;

    let dl = (a[0] as u32 & 15) + (b[0] as u32 & 15);
    let dh = (a[0] as u32 >> 4) + (b[0] as u32 >> 4);
    d[0] = ((dh << 4)
        .wrapping_add(dl)
        .wrapping_add(!(dl.wrapping_sub(15)) >> 31)) as u16;

    for u in 0..blen {
        let f = b[1 + u] as u32;
        let mut cc: u32 = 0;
        for v in 0..alen {
            let z = d[1 + u + v] as u32 + MUL15(f, a[1 + v] as u32) + cc;
            cc = z >> 15;
            d[1 + u + v] = (z & 0x7FFF) as u16;
        }
        d[1 + u + alen] = cc as u16;
    }
}
