/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Aggregate EC implementation `br_ec_all_m31` and the default selector
//! (`src/ec/ec_all_m31.c`, `src/ec/ec_default.c`).
//!
//! `br_ec_all_m31` wraps the specialised implementations:
//!
//! * `br_ec_c25519_i31` for Curve25519 (the C `_m31`/`_m64` variants give the
//!   same result and are deferred);
//! * `br_ec_p256_m31` for NIST P-256;
//! * `br_ec_prime_i31` for the other curves (P-384, P-521).

use super::{
    br_ec_c25519_i31, br_ec_impl, br_ec_p256_m31, br_ec_prime_i31, BR_EC_curve25519,
    BR_EC_secp256r1,
};

fn api_generator(curve: i32) -> &'static [u8] {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.generator)(curve),
        BR_EC_curve25519 => (br_ec_c25519_i31.generator)(curve),
        _ => (br_ec_prime_i31.generator)(curve),
    }
}

fn api_order(curve: i32) -> &'static [u8] {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.order)(curve),
        BR_EC_curve25519 => (br_ec_c25519_i31.order)(curve),
        _ => (br_ec_prime_i31.order)(curve),
    }
}

fn api_xoff(curve: i32, len: &mut usize) -> usize {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.xoff)(curve, len),
        BR_EC_curve25519 => (br_ec_c25519_i31.xoff)(curve, len),
        _ => (br_ec_prime_i31.xoff)(curve, len),
    }
}

fn api_mul(g: &mut [u8], kb: &[u8], curve: i32) -> u32 {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.mul)(g, kb, curve),
        BR_EC_curve25519 => (br_ec_c25519_i31.mul)(g, kb, curve),
        _ => (br_ec_prime_i31.mul)(g, kb, curve),
    }
}

fn api_mulgen(r: &mut [u8], x: &[u8], curve: i32) -> usize {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.mulgen)(r, x, curve),
        BR_EC_curve25519 => (br_ec_c25519_i31.mulgen)(r, x, curve),
        _ => (br_ec_prime_i31.mulgen)(r, x, curve),
    }
}

fn api_muladd(a: &mut [u8], b: Option<&[u8]>, x: &[u8], y: &[u8], curve: i32) -> u32 {
    match curve {
        BR_EC_secp256r1 => (br_ec_p256_m31.muladd)(a, b, x, y, curve),
        BR_EC_curve25519 => (br_ec_c25519_i31.muladd)(a, b, x, y, curve),
        _ => (br_ec_prime_i31.muladd)(a, b, x, y, curve),
    }
}

/// see bearssl_ec.h
pub static br_ec_all_m31: br_ec_impl = br_ec_impl {
    supported_curves: 0x23800000,
    generator: api_generator,
    order: api_order,
    xoff: api_xoff,
    mul: api_mul,
    mulgen: api_mulgen,
    muladd: api_muladd,
};

/// see bearssl_ec.h
pub fn br_ec_get_default() -> &'static br_ec_impl {
    &br_ec_all_m31
}
