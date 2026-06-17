/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_rshift` (mirrors `src/int/i15_rshift.c`).

/// Right-shift an integer. The shift amount must be lower than 15 bits.
pub fn br_i15_rshift(x: &mut [u16], count: i32) {
    let count = count as u32;
    let len = ((x[0] + 15) >> 4) as usize;
    if len == 0 {
        return;
    }
    let mut r = (x[1] as u32) >> count;
    for u in 2..=len {
        let w = x[u] as u32;
        x[u - 1] = (((w << (15 - count)) | r) & 0x7FFF) as u16;
        r = w >> count;
    }
    x[len] = r as u16;
}
