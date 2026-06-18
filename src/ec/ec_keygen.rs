/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! EC key-pair generation (`src/ec/ec_keygen.c`).

use super::br_ec_impl;
use crate::rand::PrngState;

/// see bearssl_ec.h
///
/// Generates a new EC private key, writing the scalar (big-endian) into `kbuf`.
/// The scalar is a uniformly random value in `[1, n-1]`, generated with
/// rejection sampling against the curve order `n`. Returns the length of the
/// generated scalar, or 0 on error (unsupported curve). If `kbuf` is `None`,
/// the key is not generated and the required length is returned.
///
/// Deviation from the C source: the C function also fills a `br_ec_private_key`
/// out-parameter, whose `x` field aliases `kbuf`. In the Rust port,
/// `br_ec_private_key::x` is a borrowed slice, so the key cannot hold a
/// reference into `kbuf` while `kbuf` is also passed in as `&mut`. The caller
/// builds the key from the returned length, e.g.
/// `br_ec_private_key { curve, x: &kbuf[..len] }`.
pub fn br_ec_keygen(
    rng_ctx: &mut dyn PrngState,
    impl_: &br_ec_impl,
    kbuf: Option<&mut [u8]>,
    curve: i32,
) -> usize {
    if curve < 0 || curve >= 32 || ((impl_.supported_curves >> curve) & 1) == 0 {
        return 0;
    }
    let order_full = (impl_.order)(curve);

    // Skip leading zero bytes of the order.
    let mut off = 0usize;
    let mut len = order_full.len();
    while len > 0 && order_full[off] == 0 {
        off += 1;
        len -= 1;
    }
    let order = &order_full[off..off + len];

    let buf = match kbuf {
        None => return len,
        Some(b) => b,
    };
    if len == 0 {
        return len;
    }

    let mut mask = order[0] as u32;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;

    // We generate sequences of random bits of the right size, until the value
    // is strictly lower than the curve order (we also check for all-zero
    // values, which are invalid).
    loop {
        rng_ctx.generate(&mut buf[..len]);
        buf[0] &= mask as u8;
        let mut cc = 0u32;
        let mut zz = 0u8;
        let mut u = len;
        while u > 0 {
            u -= 1;
            cc = (((buf[u] as u32).wrapping_sub(order[u] as u32).wrapping_sub(cc)) >> 8) & 1;
            zz |= buf[u];
        }
        if cc != 0 && zz != 0 {
            break;
        }
    }

    len
}
