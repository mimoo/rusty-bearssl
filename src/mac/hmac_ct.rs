/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Constant-time HMAC output (`src/mac/hmac_ct.c`), as used by the TLS record
//! MAC to mitigate Lucky-13 style timing attacks.

use super::block_size;
use super::hmac::br_hmac_context;
use crate::codec::br_ccopy as CCOPY;
use crate::hash::{br_hash_class, BR_HASHDESC_MD_PADDING_128, BR_HASHDESC_MD_PADDING_BE};
use crate::inner::{EQ, LE, LT, MUX};

#[inline(always)]
fn hash_size(dig: &br_hash_class) -> usize {
    dig.out_size()
}

/// see bearssl.h
///
/// Computes the HMAC over `data` (`len` bytes) in such a way that the amount of
/// work depends only on `min_len`/`max_len`, not on the actual `len`. `len`
/// must lie in `[min_len, max_len]`.
pub fn br_hmac_outCT(
    ctx: &br_hmac_context,
    data: &[u8],
    len: usize,
    min_len: usize,
    max_len: usize,
    out: &mut [u8],
) -> usize {
    // Copy the current inner-hash context (clone the boxed running state).
    let mut hc = ctx.dig.clone();
    let dig = hc.vtable();

    let be = (dig.desc & BR_HASHDESC_MD_PADDING_BE) != 0;
    let mut po: u32 = 9;
    if (dig.desc & BR_HASHDESC_MD_PADDING_128) != 0 {
        po += 8;
    }
    let bs = block_size(dig) as u32;
    let hlen = hash_size(dig);

    let mut data_off = 0usize;
    let mut len = len as u32;
    let mut max_len = max_len as u32;

    let mut tmp1 = [0u8; 64];
    let mut tmp2 = [0u8; 64];

    let mut count = hc.state(&mut tmp1);
    let bit_len = (count + (len as u64)) << 3;

    // Process the blocks we are sure to use (no MUX needed, and keeps the
    // remaining lengths within 32 bits).
    let ncount = (count + (min_len as u64)) & !((bs - 1) as u64);
    if ncount > count {
        let zlen = (ncount - count) as usize;
        hc.update(&data[data_off..data_off + zlen]);
        data_off += zlen;
        len -= zlen as u32;
        max_len -= zlen as u32;
        count = ncount;
    }

    let kr = (count as u32) & (bs - 1);
    let kz = ((kr + len + po + bs - 1) & !(bs - 1)) - 1 - kr;
    let kl = kz - 7;
    let km = ((kr + max_len + po + bs - 1) & !(bs - 1)) - kr;

    for u in 0..km {
        let d: u32 = if u < max_len {
            data[data_off + u as usize] as u32
        } else {
            0x00
        };
        let v = (kr + u) & (bs - 1);
        let e: u32 = if v >= (bs - 8) {
            let j = (v - (bs - 8)) << 3;
            let ee = if be {
                (bit_len >> (56 - j)) as u32
            } else {
                (bit_len >> j) as u32
            };
            ee & 0xFF
        } else {
            0x00
        };
        let x0 = MUX(EQ(u, len), 0x80, d);
        let x1 = MUX(LT(u, kl), 0x00, e);
        let xb = [MUX(LE(u, len), x0, x1) as u8];
        hc.update(&xb);
        if v == (bs - 1) {
            hc.state(&mut tmp1);
            CCOPY(EQ(u, kz), &mut tmp2, &tmp1, hlen);
        }
    }

    // Inner hash output is in tmp2[]; finish with the outer hash.
    let mut hc2 = (dig.new)();
    hc2.set_state(&ctx.kso, bs as u64);
    hc2.update(&tmp2[..hlen]);
    hc2.out(&mut tmp2);
    out[..ctx.out_len].copy_from_slice(&tmp2[..ctx.out_len]);
    ctx.out_len
}
