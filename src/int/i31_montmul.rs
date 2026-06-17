/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_montymul` (mirrors `src/int/i31_montmul.c`).

use super::br_i31_zero;
use super::i31_sub::br_i31_sub;
use crate::inner::{MUL31, MUL31_lo, NEQ, NOT};

/// Compute a modular Montgomery multiplication: d <- x*y/R mod m. d[] must be
/// distinct from x, y and m; x and y must be numerically lower than m. m0i is
/// -(1/m0) mod 2^31.
pub fn br_i31_montymul(d: &mut [u32], x: &[u32], y: &[u32], m: &[u32], m0i: u32) {
    let len = ((m[0] + 31) >> 5) as usize;
    let len4 = len & !3usize;
    br_i31_zero(d, m[0]);
    let mut dh: u64 = 0;
    for u in 0..len {
        let xu = x[u + 1];
        let f = MUL31_lo(d[1].wrapping_add(MUL31_lo(x[u + 1], y[1])), m0i);

        let mut r: u64 = 0;
        let mut v = 0usize;
        while v < len4 {
            let mut z = d[v + 1] as u64 + MUL31(xu, y[v + 1]) + MUL31(f, m[v + 1]) + r;
            r = z >> 31;
            d[v] = (z as u32) & 0x7FFFFFFF;
            z = d[v + 2] as u64 + MUL31(xu, y[v + 2]) + MUL31(f, m[v + 2]) + r;
            r = z >> 31;
            d[v + 1] = (z as u32) & 0x7FFFFFFF;
            z = d[v + 3] as u64 + MUL31(xu, y[v + 3]) + MUL31(f, m[v + 3]) + r;
            r = z >> 31;
            d[v + 2] = (z as u32) & 0x7FFFFFFF;
            z = d[v + 4] as u64 + MUL31(xu, y[v + 4]) + MUL31(f, m[v + 4]) + r;
            r = z >> 31;
            d[v + 3] = (z as u32) & 0x7FFFFFFF;
            v += 4;
        }
        while v < len {
            let z = d[v + 1] as u64 + MUL31(xu, y[v + 1]) + MUL31(f, m[v + 1]) + r;
            r = z >> 31;
            d[v] = (z as u32) & 0x7FFFFFFF;
            v += 1;
        }

        dh = dh.wrapping_add(r);
        d[len] = (dh as u32) & 0x7FFFFFFF;
        dh >>= 31;
    }

    d[0] = m[0];

    let ctl = NEQ(dh as u32, 0) | NOT(br_i31_sub(d, m, 0));
    br_i31_sub(d, m, ctl);
}
