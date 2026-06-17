/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_modpow_opt` (mirrors `src/int/i31_modpow2.c`).

use super::ccopy_words;
use super::i31_fmont::br_i31_from_monty;
use super::i31_montmul::br_i31_montymul;
use super::i31_muladd::br_i31_muladd_small;
use super::i31_tmont::br_i31_to_monty;
use super::br_i31_zero;
use crate::inner::{EQ, NEQ};

/// Compute a modular exponentiation, with windowing if tmp[] is large enough.
/// Returns 1 on success, 0 if tmp[] is too short.
pub fn br_i31_modpow_opt(
    x: &mut [u32],
    mut e: &[u8],
    mut elen: usize,
    m: &[u32],
    m0i: u32,
    tmp: &mut [u32],
    twlen: usize,
) -> u32 {
    // Get modulus size (in words, including header word), rounded up to even.
    let mut mwlen = ((m[0] + 63) >> 5) as usize;
    let mlen = mwlen; // number of words to copy for a value
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

    br_i31_to_monty(x, m);

    // Compute window contents. t1 = tmp[0..], t2 = tmp[mwlen..].
    if win_len == 1 {
        // memcpy(t2, x, mlen)
        tmp[mwlen..mwlen + mlen].copy_from_slice(&x[..mlen]);
    } else {
        // memcpy(t2 + mwlen, x, mlen); base = t2 + mwlen
        tmp[(mwlen << 1)..(mwlen << 1) + mlen].copy_from_slice(&x[..mlen]);
        let mut base = mwlen << 1; // index of t2[mwlen] == t2 base + mwlen
        for _u in 2..(1usize << win_len) {
            // montymul(base + mwlen, base, x, m, m0i)
            let (lo, hi) = tmp.split_at_mut(base + mwlen);
            br_i31_montymul(&mut hi[..mwlen], &lo[base..base + mwlen], x, m, m0i);
            base += mwlen;
        }
    }

    // Set x to 1, in Montgomery representation.
    br_i31_zero(x, m[0]);
    x[((m[0] + 31) >> 5) as usize] = 1;
    br_i31_muladd_small(x, 0, m);

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
            // montymul(t1, x, x, m, m0i); memcpy(x, t1, mlen)
            br_i31_montymul(&mut tmp[..mwlen], x, x, m, m0i);
            x[..mlen].copy_from_slice(&tmp[..mlen]);
        }

        if win_len > 1 {
            // br_i31_zero(t2, m[0]); base = t2 + mwlen
            br_i31_zero(&mut tmp[mwlen..], m[0]);
            for u in 1..(1u32 << k) {
                let mask = EQ(u, bits).wrapping_neg();
                let base = mwlen + (u as usize) * mwlen;
                for v in 1..mwlen {
                    tmp[mwlen + v] |= mask & tmp[base + v];
                }
            }
        }

        // montymul(t1, x, t2, m, m0i)
        {
            let (t1s, t2s) = tmp.split_at_mut(mwlen);
            br_i31_montymul(&mut t1s[..mwlen], x, &t2s[..mwlen], m, m0i);
        }
        ccopy_words(NEQ(bits, 0), x, &tmp[..mlen], mlen);
    }

    br_i31_from_monty(x, m, m0i);
    1
}
