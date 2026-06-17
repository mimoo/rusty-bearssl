/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_rshift` (mirrors `src/int/i31_rshift.c`).

/// Right-shift an integer. The shift amount must be lower than 31 bits.
pub fn br_i31_rshift(x: &mut [u32], count: i32) {
    let count = count as u32;
    let len = ((x[0] + 31) >> 5) as usize;
    if len == 0 {
        return;
    }
    let mut r = x[1] >> count;
    for u in 2..=len {
        let w = x[u];
        x[u - 1] = ((w << (31 - count)) | r) & 0x7FFFFFFF;
        r = w >> count;
    }
    x[len] = r;
}
