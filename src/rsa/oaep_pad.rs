/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_oaep_pad` (mirrors `src/rsa/rsa_oaep_pad.c`).

use super::br_rsa_public_key;
use crate::hash::{br_digest_size, br_hash_class, br_mgf1_xor};
use crate::rand::PrngState;

/// Hash `src` into `dst` with the given hash function.
fn hash_data(dig: &'static br_hash_class, dst: &mut [u8], src: &[u8]) {
    let mut hc = (dig.new)();
    hc.update(src);
    hc.out(dst);
}

/// see inner.h
///
/// Apply OAEP padding of `src` for public key `pk` into `dst`. Returns the
/// padded length (modulus length, in bytes), or 0 on error. `src` may overlap
/// with `dst`.
pub fn br_rsa_oaep_pad(
    rnd: &mut dyn PrngState,
    dig: &'static br_hash_class,
    label: &[u8],
    pk: &br_rsa_public_key,
    dst: &mut [u8],
    src: &[u8],
) -> usize {
    let hlen = br_digest_size(dig);
    let src_len = src.len();
    let dst_max_len = dst.len();

    // Compute actual modulus length (in bytes).
    let mut k = pk.n.len();
    while k > 0 && pk.n[k - 1] == 0 {
        k -= 1;
    }

    // Error if the modulus is too short, the source message is too long, or the
    // destination buffer is too short.
    if k < ((hlen << 1) + 2) || src_len > (k - (hlen << 1) - 2) || dst_max_len < k {
        return 0;
    }

    // Assemble: DB = lHash || PS || 0x01 || M. We place M first. The C code uses
    // memmove to allow `src` and `dst` to overlap; in this port the borrow
    // checker guarantees `src` and `dst` are distinct, so a copy suffices.
    let buf = dst;
    buf[k - src_len..k].copy_from_slice(&src[..src_len]);
    hash_data(dig, &mut buf[1 + hlen..], label);
    for b in buf[1 + (hlen << 1)..1 + (hlen << 1) + (k - src_len - (hlen << 1) - 2)].iter_mut() {
        *b = 0;
    }
    buf[k - src_len - 1] = 0x01;

    // Make the random seed at buf[1..1+hlen].
    rnd.generate(&mut buf[1..1 + hlen]);

    // Mask DB with the mask generated from the seed.
    {
        let (lo, hi) = buf.split_at_mut(1 + hlen);
        // lo = buf[0..1+hlen]; seed is lo[1..1+hlen]. hi = buf[1+hlen..].
        br_mgf1_xor(hi, k - hlen - 1, dig, &lo[1..1 + hlen]);
    }

    // Mask the seed with the mask generated from the masked DB.
    {
        let (lo, hi) = buf.split_at_mut(1 + hlen);
        br_mgf1_xor(&mut lo[1..], hlen, dig, &hi[..k - hlen - 1]);
    }

    // Padding result: EM = 0x00 || maskedSeed || maskedDB.
    buf[0] = 0x00;
    k
}
