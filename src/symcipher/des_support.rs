/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Shared DES helpers (`src/symcipher/des_support.c`): the IP / inverse-IP
//! permutations, the per-unit key schedule (PC-1 + rotations), and the subkey
//! reversal used to turn an encryption schedule into a decryption schedule.

use crate::inner::br_dec32be;

/// see inner.h
pub fn br_des_do_IP(xl: &mut u32, xr: &mut u32) {
    /*
     * Permutation algorithm is initially from Richard Outerbridge;
     * implementation here is adapted from Crypto++ "des.cpp" file
     * (which is in public domain).
     */
    let mut l = *xl;
    let mut r = *xr;
    let mut t;
    t = ((l >> 4) ^ r) & 0x0F0F0F0F;
    r ^= t;
    l ^= t << 4;
    t = ((l >> 16) ^ r) & 0x0000FFFF;
    r ^= t;
    l ^= t << 16;
    t = ((r >> 2) ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = ((r >> 8) ^ l) & 0x00FF00FF;
    l ^= t;
    r ^= t << 8;
    t = ((l >> 1) ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    *xl = l;
    *xr = r;
}

/// see inner.h
pub fn br_des_do_invIP(xl: &mut u32, xr: &mut u32) {
    /*
     * See br_des_do_IP().
     */
    let mut l = *xl;
    let mut r = *xr;
    let mut t;
    t = ((l >> 1) ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    t = ((r >> 8) ^ l) & 0x00FF00FF;
    l ^= t;
    r ^= t << 8;
    t = ((r >> 2) ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = ((l >> 16) ^ r) & 0x0000FFFF;
    r ^= t;
    l ^= t << 16;
    t = ((l >> 4) ^ r) & 0x0F0F0F0F;
    r ^= t;
    l ^= t << 4;
    *xl = l;
    *xr = r;
}

/// see inner.h
pub fn br_des_keysched_unit(skey: &mut [u32], key: &[u8]) {
    let mut xl = br_dec32be(key);
    let mut xr = br_dec32be(&key[4..]);

    br_des_do_IP(&mut xl, &mut xr);
    let mut kl = ((xr & 0xFF000000) >> 4)
        | ((xl & 0xFF000000) >> 12)
        | ((xr & 0x00FF0000) >> 12)
        | ((xl & 0x00FF0000) >> 20);
    let mut kr = ((xr & 0x000000FF) << 20)
        | ((xl & 0x0000FF00) << 4)
        | ((xr & 0x0000FF00) >> 4)
        | ((xl & 0x000F0000) >> 16);

    /*
     * For each round, rotate the two 28-bit words kl and kr.
     * The extraction of the 48-bit subkey (PC-2) is not done yet.
     */
    for i in 0..16 {
        if ((1u32 << i) & 0x8103) != 0 {
            kl = (kl << 1) | (kl >> 27);
            kr = (kr << 1) | (kr >> 27);
        } else {
            kl = (kl << 2) | (kl >> 26);
            kr = (kr << 2) | (kr >> 26);
        }
        kl &= 0x0FFFFFFF;
        kr &= 0x0FFFFFFF;
        skey[(i << 1) + 0] = kl;
        skey[(i << 1) + 1] = kr;
    }
}

/// see inner.h
pub fn br_des_rev_skey(skey: &mut [u32]) {
    let mut i = 0;
    while i < 16 {
        skey.swap(i, 30 - i);
        skey.swap(i + 1, 31 - i);
        i += 2;
    }
}
