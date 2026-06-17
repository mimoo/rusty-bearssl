/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_oaep_unpad` (mirrors `src/rsa/rsa_oaep_unpad.c`).

use crate::hash::{br_digest_size, br_hash_class, br_mgf1_xor};
use crate::inner::{EQ, GE, NOT};

/// Hash `src` and XOR the result into the first `hlen` bytes of `dst`.
fn xor_hash_data(dig: &'static br_hash_class, dst: &mut [u8], src: &[u8]) {
    let mut hc = (dig.new)();
    let mut tmp = [0u8; 64];
    hc.update(src);
    hc.out(&mut tmp);
    let hlen = br_digest_size(dig);
    for u in 0..hlen {
        dst[u] ^= tmp[u];
    }
}

/// see inner.h
///
/// Verify and strip OAEP padding from `data` in place. On success, the
/// decrypted message is moved to the front of `data`, `*len` is updated, and 1
/// is returned; otherwise `*len` is unchanged and 0 is returned.
pub fn br_rsa_oaep_unpad(
    dig: &'static br_hash_class,
    label: &[u8],
    data: &mut [u8],
    len: &mut usize,
) -> u32 {
    let hlen = br_digest_size(dig);
    let mut k = *len;
    let buf = data;

    // There must be room for the padding.
    if k < ((hlen << 1) + 2) {
        return 0;
    }

    // Unmask the seed, then the DB value.
    {
        let (lo, hi) = buf.split_at_mut(1 + hlen);
        br_mgf1_xor(&mut lo[1..], hlen, dig, &hi[..k - hlen - 1]);
    }
    {
        let (lo, hi) = buf.split_at_mut(1 + hlen);
        br_mgf1_xor(hi, k - hlen - 1, dig, &lo[1..1 + hlen]);
    }

    // Hash the label and XOR it with the value in the array.
    xor_hash_data(dig, &mut buf[1 + hlen..], label);

    // At this point, if the padding was correct, we should have:
    //   0x00 || seed || 0x00 ... 0x00 0x01 || M
    // Count leading zero bytes (after the seed) and check the next byte == 0x01,
    // in constant-time.
    let mut r: u32 = 1 - ((buf[0] as u32 + 0xFF) >> 8);
    let mut s: u32 = 0;
    let mut zlen: u32 = 0;
    for u in (hlen + 1)..k {
        let w = buf[u] as u32;
        // nz == 1 only for the first non-zero byte.
        let nz = r & ((w + 0xFF) >> 8);
        s |= nz & EQ(w, 0x01);
        r &= NOT(nz);
        zlen += r;
    }

    // Padding is correct only if s == 1, and zlen >= hlen.
    s &= GE(zlen, hlen as u32);

    // Padding verified; conditional jumps are now allowed.
    if s != 0 {
        let plen = 2 + hlen + zlen as usize;
        k -= plen;
        buf.copy_within(plen..plen + k, 0);
        *len = k;
    }
    s
}
