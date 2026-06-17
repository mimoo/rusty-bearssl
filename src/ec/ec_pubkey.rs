/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Compute an EC public key from a private key (`src/ec/ec_pubkey.c`).

use super::{br_ec_impl, br_ec_private_key};

static POINT_LEN: [u8; 31] = [
    0,   // 0: not a valid curve ID
    43,  // sect163k1
    43,  // sect163r1
    43,  // sect163r2
    51,  // sect193r1
    51,  // sect193r2
    61,  // sect233k1
    61,  // sect233r1
    61,  // sect239k1
    73,  // sect283k1
    73,  // sect283r1
    105, // sect409k1
    105, // sect409r1
    145, // sect571k1
    145, // sect571r1
    41,  // secp160k1
    41,  // secp160r1
    41,  // secp160r2
    49,  // secp192k1
    49,  // secp192r1
    57,  // secp224k1
    57,  // secp224r1
    65,  // secp256k1
    65,  // secp256r1
    97,  // secp384r1
    133, // secp521r1
    65,  // brainpoolP256r1
    97,  // brainpoolP384r1
    129, // brainpoolP512r1
    32,  // curve25519
    56,  // curve448
];

/// see bearssl_ec.h
///
/// Computes the public key point for `sk` using `impl_`, writing it into
/// `kbuf` (if `Some`). Returns the public-key point length, or 0 on error
/// (unsupported curve). If `kbuf` is `None`, the point is not computed and the
/// maximum length is returned.
pub fn br_ec_compute_pub(
    impl_: &br_ec_impl,
    kbuf: Option<&mut [u8]>,
    sk: &br_ec_private_key,
) -> usize {
    let curve = sk.curve;
    if curve < 0
        || curve >= 32
        || curve >= POINT_LEN.len() as i32
        || ((impl_.supported_curves >> curve) & 1) == 0
    {
        return 0;
    }
    match kbuf {
        None => POINT_LEN[curve as usize] as usize,
        Some(buf) => (impl_.mulgen)(buf, sk.x, curve),
    }
}
