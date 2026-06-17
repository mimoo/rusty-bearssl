/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_divrem` and its `br_rem`/`br_div` wrappers (mirrors `src/int/i32_div32.c`
//! and the inline definitions in `inner.h`).

use crate::inner::{EQ, GE, MUX};

/// Constant-time division. The dividend hi:lo is divided by the divisor d; the
/// quotient is returned and the remainder is written in *r. If hi == d, then
/// the quotient does not fit on 32 bits and the returned value is truncated. If
/// hi > d, returned values are indeterminate.
pub fn br_divrem(mut hi: u32, mut lo: u32, d: u32, r: &mut u32) -> u32 {
    let mut q: u32 = 0;
    let ch = EQ(hi, d);
    hi = MUX(ch, 0, hi);
    let mut k = 31;
    while k > 0 {
        let j = 32 - k;
        let w = (hi << j) | (lo >> k);
        let ctl = GE(w, d) | (hi >> k);
        let hi2 = w.wrapping_sub(d) >> j;
        let lo2 = lo.wrapping_sub(d << k);
        hi = MUX(ctl, hi2, hi);
        lo = MUX(ctl, lo2, lo);
        q |= ctl << k;
        k -= 1;
    }
    let cf = GE(lo, d) | hi;
    q |= cf;
    *r = MUX(cf, lo.wrapping_sub(d), lo);
    q
}

/// Wrapper for [`br_divrem`]: the remainder is returned, quotient discarded.
pub fn br_rem(hi: u32, lo: u32, d: u32) -> u32 {
    let mut r = 0u32;
    br_divrem(hi, lo, d, &mut r);
    r
}

/// Wrapper for [`br_divrem`]: the quotient is returned, remainder discarded.
pub fn br_div(hi: u32, lo: u32, d: u32) -> u32 {
    let mut r = 0u32;
    br_divrem(hi, lo, d, &mut r)
}
