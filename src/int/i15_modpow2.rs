/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i15_modpow_opt` (mirrors `src/int/i15_modpow2.c`).

use super::ccopy_words16;
use super::i15_fmont::br_i15_from_monty;
use super::i15_montmul::br_i15_montymul;
use super::i15_muladd::br_i15_muladd_small;
use super::i15_tmont::br_i15_to_monty;
use super::br_i15_zero;
use crate::inner::{EQ, NEQ};

/// Compute a modular exponentiation, with windowing if tmp[] is large enough.
/// Returns 1 on success, 0 if tmp[] is too short.
pub fn br_i15_modpow_opt(
    x: &mut [u16],
    mut e: &[u8],
    mut elen: usize,
    m: &[u16],
    m0i: u16,
    tmp: &mut [u16],
    twlen: usize,
) -> u32 {
    let mut mwlen = ((m[0] + 31) >> 4) as usize;
    let mlen = mwlen;
    mwlen += mwlen & 1;

    if twlen < (mwlen << 1) {
        return 0;
    }
    let mut win_len = 5i32;
    while win_len > 1 {
        if (((1usize << win_len) + 1) * mwlen) <= twlen {
            break;
        }
        win_len -= 1;
    }

    br_i15_to_monty(x, m);

    if win_len == 1 {
        tmp[mwlen..mwlen + mlen].copy_from_slice(&x[..mlen]);
    } else {
        tmp[(mwlen << 1)..(mwlen << 1) + mlen].copy_from_slice(&x[..mlen]);
        let mut base = mwlen << 1;
        for _u in 2..(1usize << win_len) {
            let (lo, hi) = tmp.split_at_mut(base + mwlen);
            br_i15_montymul(&mut hi[..mwlen], &lo[base..base + mwlen], x, m, m0i);
            base += mwlen;
        }
    }

    br_i15_zero(x, m[0]);
    x[((m[0] + 15) >> 4) as usize] = 1;
    br_i15_muladd_small(x, 0, m);

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

        for _i in 0..k {
            br_i15_montymul(&mut tmp[..mwlen], x, x, m, m0i);
            x[..mlen].copy_from_slice(&tmp[..mlen]);
        }

        if win_len > 1 {
            br_i15_zero(&mut tmp[mwlen..], m[0]);
            for u in 1..(1u32 << k) {
                let mask = (EQ(u, bits).wrapping_neg() & 0xFFFF) as u16;
                let base = mwlen + (u as usize) * mwlen;
                for v in 1..mwlen {
                    tmp[mwlen + v] |= mask & tmp[base + v];
                }
            }
        }

        {
            let (t1s, t2s) = tmp.split_at_mut(mwlen);
            br_i15_montymul(&mut t1s[..mwlen], x, &t2s[..mwlen], m, m0i);
        }
        ccopy_words16(NEQ(bits, 0), x, &tmp[..mlen], mlen);
    }

    br_i15_from_monty(x, m, m0i);
    1
}
