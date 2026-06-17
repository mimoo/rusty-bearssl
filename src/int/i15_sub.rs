/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_sub` (mirrors `src/int/i15_sub.c`).

use crate::inner::MUX;

/// Subtract b[] from a[] and return the carry (0 or 1).
pub fn br_i15_sub(a: &mut [u16], b: &[u16], ctl: u32) -> u32 {
    let mut cc: u32 = 0;
    let m = ((a[0] + 31) >> 4) as usize;
    for u in 1..m {
        let aw = a[u] as u32;
        let bw = b[u] as u32;
        let naw = aw.wrapping_sub(bw).wrapping_sub(cc);
        cc = naw >> 31;
        a[u] = MUX(ctl, naw & 0x7FFF, aw) as u16;
    }
    cc
}
