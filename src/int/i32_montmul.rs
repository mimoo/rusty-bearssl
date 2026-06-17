/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i32_montymul` (mirrors `src/int/i32_montmul.c`).

use super::br_i32_zero;
use super::i32_sub::br_i32_sub;
use crate::inner::{MUL, NEQ, NOT};

/// Compute a modular Montgomery multiplication: d <- x*y/R mod m.
pub fn br_i32_montymul(d: &mut [u32], x: &[u32], y: &[u32], m: &[u32], m0i: u32) {
    let len = ((m[0] + 31) >> 5) as usize;
    br_i32_zero(d, m[0]);
    let mut dh: u64 = 0;
    for u in 0..len {
        let xu = x[u + 1];
        let f = (d[1].wrapping_add(x[u + 1].wrapping_mul(y[1]))).wrapping_mul(m0i);
        let mut r1: u64 = 0;
        let mut r2: u64 = 0;
        for v in 0..len {
            let mut z = d[v + 1] as u64 + MUL(xu, y[v + 1]) + r1;
            r1 = z >> 32;
            let t = z as u32;
            z = t as u64 + MUL(f, m[v + 1]) + r2;
            r2 = z >> 32;
            if v != 0 {
                d[v] = z as u32;
            }
        }
        let zh = dh + r1 + r2;
        d[len] = zh as u32;
        dh = zh >> 32;
    }

    let ctl = NEQ(dh as u32, 0) | NOT(br_i32_sub(d, m, 0));
    br_i32_sub(d, m, ctl);
}
