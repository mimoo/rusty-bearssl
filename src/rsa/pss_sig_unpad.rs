/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_pss_sig_unpad` (mirrors `src/rsa/rsa_pss_sig_unpad.c`).

use super::br_rsa_public_key;
use crate::hash::{br_digest_size, br_hash_class, br_mgf1_xor};
use crate::inner::{BIT_LENGTH, EQ0};

/// see inner.h
///
/// Verify the PSS padding of the decrypted value `x`. Returns 1 on success, 0
/// on error.
pub fn br_rsa_pss_sig_unpad(
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    pk: &br_rsa_public_key,
    x: &mut [u8],
) -> u32 {
    let hash_len = br_digest_size(hf_data);
    let mut tmp = [0u8; 64];

    // Value r will be set to a non-zero value if any test fails.
    let mut r: u32 = 0;

    // The value bit length (as an integer) must be strictly less than that of
    // the modulus.
    let mut u = 0usize;
    while u < pk.n.len() {
        if pk.n[u] != 0 {
            break;
        }
        u += 1;
    }
    if u == pk.n.len() {
        return 0;
    }
    let mut n_bitlen = BIT_LENGTH(pk.n[u] as u32) + (((pk.n.len() - u - 1) as u32) << 3);
    n_bitlen -= 1;
    let mut base = 0usize;
    if (n_bitlen & 7) == 0 {
        r |= x[0] as u32;
        base = 1;
    } else {
        r |= (x[0] & (0xFFu8 << (n_bitlen & 7))) as u32;
    }
    let xlen = ((n_bitlen + 7) >> 3) as usize;
    let x = &mut x[base..];

    // Check that the modulus is large enough.
    if hash_len > xlen || salt_len > xlen || (hash_len + salt_len + 2) > xlen {
        return 0;
    }

    // Check value of rightmost byte.
    r |= (x[xlen - 1] ^ 0xBC) as u32;

    // Generate the mask and XOR it into the first bytes to reveal PS; also mask
    // out the leading bits.
    let seed_off = xlen - hash_len - 1;
    {
        let (lo, hi) = x.split_at_mut(seed_off);
        br_mgf1_xor(lo, xlen - hash_len - 1, hf_mgf1, &hi[..hash_len]);
    }
    if (n_bitlen & 7) != 0 {
        x[0] &= 0xFFu8 >> (8 - (n_bitlen & 7));
    }

    // Check that all padding bytes have the expected value.
    for u in 0..(xlen - hash_len - salt_len - 2) {
        r |= x[u] as u32;
    }
    r |= (x[xlen - hash_len - salt_len - 2] ^ 0x01) as u32;

    // Recompute H.
    let salt_off = xlen - hash_len - salt_len - 1;
    {
        let mut hc = (hf_data.new)();
        for b in tmp[..8].iter_mut() {
            *b = 0;
        }
        hc.update(&tmp[..8]);
        hc.update(&hash[..hash_len]);
        hc.update(&x[salt_off..salt_off + salt_len]);
        hc.out(&mut tmp);
    }

    // Check that the recomputed H value matches the one appearing in the string.
    for u in 0..hash_len {
        r |= (tmp[u] ^ x[(xlen - hash_len - 1) + u]) as u32;
    }

    EQ0(r as i32)
}
