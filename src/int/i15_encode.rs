/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_encode` (mirrors `src/int/i15_encode.c`).

/// Encode an integer into its big-endian unsigned representation.
pub fn br_i15_encode(dst: &mut [u8], mut len: usize, x: &[u16]) {
    let xlen = ((x[0] + 15) >> 4) as usize;
    if xlen == 0 {
        for b in dst[..len].iter_mut() {
            *b = 0;
        }
        return;
    }
    let mut u = 1usize;
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while len > 0 {
        len -= 1;
        if acc_len < 8 {
            if u <= xlen {
                acc += (x[u] as u32) << acc_len;
                u += 1;
            }
            acc_len += 15;
        }
        dst[len] = acc as u8;
        acc >>= 8;
        acc_len -= 8;
    }
}
