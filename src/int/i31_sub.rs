/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_sub` (mirrors `src/int/i31_sub.c`).

use crate::inner::MUX;

/// Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0, then a[]
/// is unmodified, but the carry is still computed and returned.
pub fn br_i31_sub(a: &mut [u32], b: &[u32], ctl: u32) -> u32 {
    let mut cc: u32 = 0;
    let m = ((a[0] + 63) >> 5) as usize;
    for u in 1..m {
        let aw = a[u];
        let bw = b[u];
        let naw = aw.wrapping_sub(bw).wrapping_sub(cc);
        cc = naw >> 31;
        a[u] = MUX(ctl, naw & 0x7FFFFFFF, aw);
    }
    cc
}
