/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_i31_reduce` (mirrors `src/int/i31_reduce.c`).

use super::i31_muladd::br_i31_muladd_small;

/// Reduce an integer a[] modulo m[], result in x[]. x must be distinct from a
/// and m. The announced bit length of x is set to that of m.
pub fn br_i31_reduce(x: &mut [u32], a: &[u32], m: &[u32]) {
    let m_bitlen = m[0];
    let mlen = ((m_bitlen + 31) >> 5) as usize;

    x[0] = m_bitlen;
    if m_bitlen == 0 {
        return;
    }

    let a_bitlen = a[0];
    let alen = ((a_bitlen + 31) >> 5) as usize;
    if a_bitlen < m_bitlen {
        x[1..1 + alen].copy_from_slice(&a[1..1 + alen]);
        for u in alen..mlen {
            x[u + 1] = 0;
        }
        return;
    }

    // memcpy(x + 1, a + 2 + (alen - mlen), (mlen - 1) * sizeof)
    let src_off = 2 + (alen - mlen);
    x[1..1 + (mlen - 1)].copy_from_slice(&a[src_off..src_off + (mlen - 1)]);
    x[mlen] = 0;
    let mut u = 1 + alen - mlen;
    while u > 0 {
        br_i31_muladd_small(x, a[u], m);
        u -= 1;
    }
}
