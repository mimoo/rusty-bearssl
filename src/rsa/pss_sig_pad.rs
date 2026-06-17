/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_pss_sig_pad` (mirrors `src/rsa/rsa_pss_sig_pad.c`).

use crate::hash::{br_digest_size, br_hash_class, br_mgf1_xor};
use crate::rand::PrngState;

/// see inner.h
///
/// Build the PSS-padded value into `x` (modulus length determined by
/// `n_bitlen`). Returns 1 on success, 0 if the modulus is too short.
pub fn br_rsa_pss_sig_pad(
    rng: Option<&mut dyn PrngState>,
    hf_data: &'static br_hash_class,
    hf_mgf1: &'static br_hash_class,
    hash: &[u8],
    salt_len: usize,
    mut n_bitlen: u32,
    x: &mut [u8],
) -> u32 {
    let hash_len = br_digest_size(hf_data);

    // The padded string is one bit smaller than the modulus; if the modulus
    // length is equal to 1 modulo 8, then the padded string will be one _byte_
    // smaller, and the leading byte is set to 0. `base` tracks that one-byte
    // advance of the C `x++`.
    n_bitlen -= 1;
    let mut base = 0usize;
    if (n_bitlen & 7) == 0 {
        x[0] = 0;
        base = 1;
    }
    let xlen = ((n_bitlen + 7) >> 3) as usize;
    let x = &mut x[base..];

    // Check that the modulus is large enough for the hash value length combined
    // with the intended salt length.
    if hash_len > xlen || salt_len > xlen || (hash_len + salt_len + 2) > xlen {
        return 0;
    }

    // Produce a random salt, placed at offset `salt_off`.
    let salt_off = xlen - hash_len - salt_len - 1;
    if salt_len != 0 {
        // `rng` is mandatory when salt_len != 0 (mirrors `(*rng)->generate`).
        rng.unwrap().generate(&mut x[salt_off..salt_off + salt_len]);
    }

    // Compute the seed (H) for MGF1, located at `seed_off`.
    let seed_off = xlen - hash_len - 1;
    {
        let mut hc = (hf_data.new)();
        for b in x[seed_off..seed_off + 8].iter_mut() {
            *b = 0;
        }
        let zeros = [0u8; 8];
        hc.update(&zeros);
        hc.update(&hash[..hash_len]);
        // salt sits at salt_off..salt_off+salt_len.
        let salt = x[salt_off..salt_off + salt_len].to_vec();
        hc.update(&salt);
        hc.out(&mut x[seed_off..]);
    }

    // Prepare string PS (padded salt). The salt is already at the right place.
    for b in x[..xlen - salt_len - hash_len - 2].iter_mut() {
        *b = 0;
    }
    x[xlen - salt_len - hash_len - 2] = 0x01;

    // Generate the mask and XOR it into PS. The seed is at seed_off, disjoint
    // from the destination [0, xlen-hash_len-1).
    {
        let (lo, hi) = x.split_at_mut(seed_off);
        // lo covers [0, seed_off) = [0, xlen-hash_len-1); the masked region has
        // length xlen-hash_len-1. hi[0..hash_len] is the seed.
        br_mgf1_xor(lo, xlen - hash_len - 1, hf_mgf1, &hi[..hash_len]);
    }

    // Clear the top bits to ensure the value is lower than the modulus.
    x[0] &= 0xFFu8 >> (((xlen as u32) << 3) - n_bitlen);

    // The seed (H) is already in the right place. Set the last byte.
    x[xlen - 1] = 0xBC;

    1
}
