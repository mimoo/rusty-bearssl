/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i62_modpow_opt` and `br_i62_modpow_opt_as_i31` (mirrors
//! `src/int/i62_modpow2.c`). This is the `BR_INT128` variant, implemented with
//! Rust's native `u128`.

use super::i31_modpow::br_i31_modpow;
use super::i31_muladd::br_i31_muladd_small;
use super::br_i31_zero;
use crate::inner::{EQ, NOT};

const MASK62: u64 = 0x3FFFFFFFFFFFFFFF;

#[inline(always)]
fn mul62_lo(x: u64, y: u64) -> u64 {
    x.wrapping_mul(y) & MASK62
}

/// Compute x*y+v1+v2 over 64-bit operands, 128-bit result split into (hi, lo).
#[inline(always)]
fn fma1(x: u64, y: u64, v1: u64, v2: u64) -> (u64, u64) {
    let z = (x as u128) * (y as u128) + (v1 as u128) + (v2 as u128);
    ((z >> 64) as u64, z as u64)
}

/// Compute x1*y1+x2*y2+v1+v2, 128-bit result split into (hi, lo).
#[inline(always)]
fn fma2(x1: u64, y1: u64, x2: u64, y2: u64, v1: u64, v2: u64) -> (u64, u64) {
    let z =
        (x1 as u128) * (y1 as u128) + (x2 as u128) * (y2 as u128) + (v1 as u128) + (v2 as u128);
    ((z >> 64) as u64, z as u64)
}

/// Subtract b from a, returning the final carry; if ctl32 is 0 then a[] is kept
/// unmodified but the carry is still computed.
fn i62_sub(a: &mut [u64], b: &[u64], num: usize, ctl32: u32) -> u32 {
    let mut cc: u64 = 0;
    let ctl32 = ctl32.wrapping_neg();
    let mask = (ctl32 as u64) | ((ctl32 as u64) << 32);
    for u in 0..num {
        let aw = a[u];
        let bw = b[u];
        let dw = aw.wrapping_sub(bw).wrapping_sub(cc);
        cc = dw >> 63;
        let dw = dw & MASK62;
        a[u] = aw ^ (mask & (dw ^ aw));
    }
    cc as u32
}

/// Montgomery multiplication over arrays of 62-bit values. d must be distinct
/// from x, y and m. Arrays are little-endian over 'num' words (no header).
fn montymul(d: &mut [u64], x: &[u64], y: &[u64], m: &[u64], num: usize, m0i: u64) {
    let num4 = 1 + ((num - 1) & !3usize);
    for w in d[..num].iter_mut() {
        *w = 0;
    }
    let mut dh: u64 = 0;
    for u in 0..num {
        let xu = x[u] << 2;
        let f = mul62_lo(d[0].wrapping_add(mul62_lo(x[u], y[0])), m0i) << 2;

        let (hi, _lo) = fma2(xu, y[0], f, m[0], d[0] << 2, 0);
        let mut r = hi;

        let mut v = 1usize;
        while v < num4 {
            let (hi, lo) = fma2(xu, y[v], f, m[v], d[v] << 2, r << 2);
            r = hi + (r >> 62);
            d[v - 1] = lo >> 2;
            let (hi, lo) = fma2(xu, y[v + 1], f, m[v + 1], d[v + 1] << 2, r << 2);
            r = hi + (r >> 62);
            d[v] = lo >> 2;
            let (hi, lo) = fma2(xu, y[v + 2], f, m[v + 2], d[v + 2] << 2, r << 2);
            r = hi + (r >> 62);
            d[v + 1] = lo >> 2;
            let (hi, lo) = fma2(xu, y[v + 3], f, m[v + 3], d[v + 3] << 2, r << 2);
            r = hi + (r >> 62);
            d[v + 2] = lo >> 2;
            v += 4;
        }
        while v < num {
            let (hi, lo) = fma2(xu, y[v], f, m[v], d[v] << 2, r << 2);
            r = hi + (r >> 62);
            d[v - 1] = lo >> 2;
            v += 1;
        }

        let zh = dh + r;
        d[num - 1] = zh & MASK62;
        dh = zh >> 62;
    }
    let ctl = (dh as u32) | NOT(i62_sub(d, m, num, 0));
    i62_sub(d, m, num, ctl);
}

/// Conversion back from Montgomery representation.
fn frommonty(x: &mut [u64], m: &[u64], num: usize, m0i: u64) {
    for _u in 0..num {
        let f = mul62_lo(x[0], m0i) << 2;
        let mut cc: u64 = 0;
        for v in 0..num {
            let (hi, lo) = fma1(f, m[v], x[v] << 2, cc);
            cc = hi << 2;
            if v != 0 {
                x[v - 1] = lo >> 2;
            }
        }
        x[num - 1] = cc >> 2;
    }
    let ctl = NOT(i62_sub(x, m, num, 0));
    i62_sub(x, m, num, ctl);
}

/// Variant of `br_i31_modpow_opt` using 64x64->128 multiplications; the
/// temporaries are 64-bit integers.
pub fn br_i62_modpow_opt(
    x31: &mut [u32],
    e: &[u8],
    elen: usize,
    m31: &[u32],
    m0i31: u32,
    tmp: &mut [u64],
    twlen: usize,
) -> u32 {
    let mw31num = ((m31[0] + 31) >> 5) as usize;
    let mw62num = (mw31num + 1) >> 1;

    // Fall back to br_i31_modpow() when there is not enough room, or for short
    // moduli (< 4 words).
    if mw31num < 4 || (mw62num << 2) > twlen {
        let txlen = mw31num + 1;
        if twlen < txlen {
            return 0;
        }
        // The C code reinterprets the 64-bit tmp[] as 32-bit words. We use a
        // separate 32-bit scratch buffer of the equivalent size.
        let mut scratch = vec![0u32; 2 * txlen];
        let (t1, t2) = scratch.split_at_mut(txlen);
        br_i31_modpow(x31, e, elen, m31, m0i31, t1, t2);
        return 1;
    }

    // Convert x to Montgomery representation using the 31-bit functions.
    for _u in 0..mw62num {
        br_i31_muladd_small(x31, 0, m31);
        br_i31_muladd_small(x31, 0, m31);
    }

    // Assemble m and x into arrays of 62-bit words. m = tmp[0..], x = tmp[mw62num..].
    {
        let (m_arr, rest) = tmp.split_at_mut(mw62num);
        let x_arr = &mut rest[..mw62num];
        let mut u = 0usize;
        while u < mw31num {
            let v = u >> 1;
            if (u + 1) == mw31num {
                m_arr[v] = m31[u + 1] as u64;
                x_arr[v] = x31[u + 1] as u64;
            } else {
                m_arr[v] = (m31[u + 1] as u64) + ((m31[u + 2] as u64) << 31);
                x_arr[v] = (x31[u + 1] as u64) + ((x31[u + 2] as u64) << 31);
            }
            u += 2;
        }
    }

    // tmp advanced past m and x; remaining length is twlen2.
    let base = mw62num << 1;
    let twlen2 = twlen - (mw62num << 1);

    // Window size.
    let mut win_len = 5i32;
    while win_len > 1 {
        if (((1usize << win_len) + 1) * mw62num) <= twlen2 {
            break;
        }
        win_len -= 1;
    }

    // m0i mod 2^62.
    let m0i_base;
    {
        let m0 = tmp[0];
        let mut m0i = m0i31 as u64;
        m0i = mul62_lo(m0i, 2u64.wrapping_add(mul62_lo(m0i, m0)));
        m0i_base = m0i;
    }
    let m0i = m0i_base;

    // t1 = tmp[base..], t2 = tmp[base + mw62num..].
    // Compute window contents.
    if win_len == 1 {
        // memcpy(t2, x, mw62num)
        let (x_part, t_part) = tmp.split_at_mut(base);
        let x_arr = &x_part[mw62num..mw62num + mw62num];
        t_part[mw62num..mw62num + mw62num].copy_from_slice(x_arr);
    } else {
        // memcpy(t2 + mw62num, x, mw62num); base2 = t2 + mw62num
        {
            let (x_part, t_part) = tmp.split_at_mut(base);
            let x_arr = &x_part[mw62num..mw62num + mw62num];
            // t2 starts at base+mw62num within tmp; t2+mw62num = base+2*mw62num.
            t_part[(2 * mw62num)..(2 * mw62num) + mw62num].copy_from_slice(x_arr);
        }
        let mut basep = base + 2 * mw62num; // index of t2[mw62num]
        for _u in 2..(1usize << win_len) {
            // montymul(basep + mw62num, basep, x, m, mw62num, m0i)
            // m = tmp[0..mw62num], x = tmp[mw62num..2*mw62num], both before base.
            let (head, tail) = tmp.split_at_mut(basep);
            // head holds m and x and earlier window entries; tail starts at basep.
            let (cur, next) = tail.split_at_mut(mw62num);
            let m_arr = &head[0..mw62num];
            let x_arr = &head[mw62num..2 * mw62num];
            montymul(&mut next[..mw62num], &cur[..mw62num], x_arr, m_arr, mw62num, m0i);
            basep += mw62num;
        }
    }

    // Set x to 1 in Montgomery representation (using 31-bit code).
    br_i31_zero(x31, m31[0]);
    x31[((m31[0] + 31) >> 5) as usize] = 1;
    br_i31_muladd_small(x31, 0, m31);
    if (mw31num & 1) != 0 {
        br_i31_muladd_small(x31, 0, m31);
    }
    {
        let (_m_arr, rest) = tmp.split_at_mut(mw62num);
        let x_arr = &mut rest[..mw62num];
        let mut u = 0usize;
        while u < mw31num {
            let v = u >> 1;
            if (u + 1) == mw31num {
                x_arr[v] = x31[u + 1] as u64;
            } else {
                x_arr[v] = (x31[u + 1] as u64) + ((x31[u + 2] as u64) << 31);
            }
            u += 2;
        }
    }

    let mut e = e;
    let mut elen = elen;
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    while acc_len > 0 || elen > 0 {
        let mut k = win_len;
        if acc_len < win_len {
            if elen > 0 {
                acc = (acc << 8) | e[0] as u32;
                e = &e[1..];
                elen -= 1;
                acc_len += 8;
            } else {
                k = acc_len;
            }
        }
        let bits = (acc >> (acc_len - k)) & ((1u32 << k) - 1);
        acc_len -= k;

        // k squarings: montymul(t1, x, x, m, ...); memcpy(x, t1).
        for _i in 0..k {
            {
                let (head, t_part) = tmp.split_at_mut(base);
                let m_arr = &head[0..mw62num];
                let x_arr = &head[mw62num..2 * mw62num];
                montymul(&mut t_part[..mw62num], x_arr, x_arr, m_arr, mw62num, m0i);
            }
            // memcpy(x, t1, mw62num): x = tmp[mw62num..2mw62num], t1 = tmp[base..]
            tmp.copy_within(base..base + mw62num, mw62num);
        }

        // Window lookup.
        if win_len > 1 {
            // memset(t2, 0, mw62num); base2 = t2 + mw62num
            for w in tmp[base + mw62num..base + 2 * mw62num].iter_mut() {
                *w = 0;
            }
            for u in 1..(1u32 << k) {
                let mask = (EQ(u, bits) as u64).wrapping_neg();
                let basep = base + mw62num + (u as usize) * mw62num;
                for v in 0..mw62num {
                    tmp[base + mw62num + v] |= mask & tmp[basep + v];
                }
            }
        }

        // montymul(t1, x, t2, m, ...)
        {
            let (head, t_part) = tmp.split_at_mut(base);
            let m_arr = &head[0..mw62num];
            let x_arr = &head[mw62num..2 * mw62num];
            // t1 = t_part[0..mw62num], t2 = t_part[mw62num..2mw62num]
            let (t1s, t2s) = t_part.split_at_mut(mw62num);
            montymul(&mut t1s[..mw62num], x_arr, &t2s[..mw62num], m_arr, mw62num, m0i);
        }
        let mask1 = (EQ(bits, 0) as u64).wrapping_neg();
        let mask2 = !mask1;
        for u in 0..mw62num {
            let xv = tmp[mw62num + u];
            let t1v = tmp[base + u];
            tmp[mw62num + u] = (mask1 & xv) | (mask2 & t1v);
        }
    }

    // Convert back from Montgomery representation.
    {
        let (m_arr, rest) = tmp.split_at_mut(mw62num);
        let x_arr = &mut rest[..mw62num];
        frommonty(x_arr, m_arr, mw62num, m0i);
    }

    // Convert result into 31-bit words.
    {
        let x_arr = &tmp[mw62num..2 * mw62num];
        let mut u = 0usize;
        while u < mw31num {
            let zw = x_arr[u >> 1];
            x31[u + 1] = (zw as u32) & 0x7FFFFFFF;
            if (u + 1) < mw31num {
                x31[u + 2] = (zw >> 31) as u32;
            }
            u += 2;
        }
    }
    1
}

/// Wrapper for [`br_i62_modpow_opt`] that uses the same type as
/// `br_i31_modpow_opt`. The tmp slice is provided as `u64` (already aligned).
pub fn br_i62_modpow_opt_as_i31(
    x31: &mut [u32],
    e: &[u8],
    elen: usize,
    m31: &[u32],
    m0i31: u32,
    tmp: &mut [u64],
    twlen: usize,
) -> u32 {
    br_i62_modpow_opt(x31, e, elen, m31, m0i31, tmp, twlen)
}
