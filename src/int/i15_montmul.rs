/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_montymul` (mirrors `src/int/i15_montmul.c`; the ARM-asm fast path is
//! omitted, only the portable C loop is ported).

use super::br_i15_zero;
use super::i15_sub::br_i15_sub;
use crate::inner::{MUL15, NEQ, NOT};

/// Compute a modular Montgomery multiplication: d <- x*y/R mod m.
pub fn br_i15_montymul(d: &mut [u16], x: &[u16], y: &[u16], m: &[u16], m0i: u16) {
    let len = ((m[0] + 15) >> 4) as usize;
    let len4 = len & !3usize;
    br_i15_zero(d, m[0]);
    let mut dh: u32 = 0;
    for u in 0..len {
        let xu = x[u + 1] as u32;
        let f = MUL15(
            (d[1] as u32).wrapping_add(MUL15(x[u + 1] as u32, y[1] as u32)) & 0x7FFF,
            m0i as u32,
        ) & 0x7FFF;

        let mut r: u32 = 0;
        let mut v = 0usize;
        while v < len4 {
            let mut z = d[v + 1] as u32 + MUL15(xu, y[v + 1] as u32) + MUL15(f, m[v + 1] as u32) + r;
            r = z >> 15;
            d[v] = (z & 0x7FFF) as u16;
            z = d[v + 2] as u32 + MUL15(xu, y[v + 2] as u32) + MUL15(f, m[v + 2] as u32) + r;
            r = z >> 15;
            d[v + 1] = (z & 0x7FFF) as u16;
            z = d[v + 3] as u32 + MUL15(xu, y[v + 3] as u32) + MUL15(f, m[v + 3] as u32) + r;
            r = z >> 15;
            d[v + 2] = (z & 0x7FFF) as u16;
            z = d[v + 4] as u32 + MUL15(xu, y[v + 4] as u32) + MUL15(f, m[v + 4] as u32) + r;
            r = z >> 15;
            d[v + 3] = (z & 0x7FFF) as u16;
            v += 4;
        }
        while v < len {
            let z = d[v + 1] as u32 + MUL15(xu, y[v + 1] as u32) + MUL15(f, m[v + 1] as u32) + r;
            r = z >> 15;
            d[v] = (z & 0x7FFF) as u16;
            v += 1;
        }

        let zh = dh + r;
        d[len] = (zh & 0x7FFF) as u16;
        dh = zh >> 15;
    }

    d[0] = m[0];

    let ctl = NEQ(dh, 0) | NOT(br_i15_sub(d, m, 0));
    br_i15_sub(d, m, ctl);
}
