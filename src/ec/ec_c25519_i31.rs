/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Curve25519 / X25519 implementation `br_ec_c25519_i31`
//! (`src/ec/ec_c25519_i31.c`).
//!
//! Uses the generic `i31` modular-integer code (31-bit words). Because of the
//! curve definition:
//!
//! * `muladd()` is not implemented (always returns 0);
//! * `order()` returns `2^255-1`, since the multiplication accepts any 32-bit
//!   scalar (it clears the top bit and low three bits systematically).

use super::br_ec_impl;
use crate::inner::NOT;
use crate::int::{
    br_i31_add, br_i31_decode_mod, br_i31_encode, br_i31_montymul, br_i31_sub, br_i31_zero,
};

/*
 * Parameters for the field:
 *   - field modulus p = 2^255-19
 *   - R^2 mod p (R = 2^(31k) for the smallest k such that R >= p)
 */

static C255_P: [u32; 10] = [
    0x00000107, 0x7FFFFFED, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0x0000007F,
];

const P0I: u32 = 0x286BCA1B;

static C255_R2: [u32; 10] = [
    0x00000107, 0x00000000, 0x02D20000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
];

static C255_A24: [u32; 10] = [
    0x00000107, 0x53000000, 0x0000468B, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
];

static GEN: [u8; 32] = [
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

fn api_generator(_curve: i32) -> &'static [u8] {
    &GEN
}

fn api_order(_curve: i32) -> &'static [u8] {
    &ORDER
}

fn api_xoff(_curve: i32, len: &mut usize) -> usize {
    *len = 32;
    0
}

fn cswap(a: &mut [u32; 10], b: &mut [u32; 10], ctl: u32) {
    let ctl = ctl.wrapping_neg();
    for i in 0..10 {
        let aw = a[i];
        let bw = b[i];
        let tw = ctl & (aw ^ bw);
        a[i] = aw ^ tw;
        b[i] = bw ^ tw;
    }
}

fn c255_add(d: &mut [u32; 10], a: &[u32; 10], b: &[u32; 10]) {
    let mut t = *a;
    let mut ctl = br_i31_add(&mut t, b, 1);
    ctl |= NOT(br_i31_sub(&mut t, &C255_P, 0));
    br_i31_sub(&mut t, &C255_P, ctl);
    *d = t;
}

fn c255_sub(d: &mut [u32; 10], a: &[u32; 10], b: &[u32; 10]) {
    let mut t = *a;
    let s = br_i31_sub(&mut t, b, 1);
    br_i31_add(&mut t, &C255_P, s);
    *d = t;
}

fn c255_mul(d: &mut [u32; 10], a: &[u32; 10], b: &[u32; 10]) {
    let mut t = [0u32; 10];
    br_i31_montymul(&mut t, a, b, &C255_P, P0I);
    *d = t;
}

fn byteswap(G: &mut [u8]) {
    for i in 0..16 {
        G.swap(i, 31 - i);
    }
}

fn api_mul(G: &mut [u8], kb: &[u8], _curve: i32) -> u32 {
    let mut x1 = [0u32; 10];
    let mut x2 = [0u32; 10];
    let mut x3 = [0u32; 10];
    let mut z2 = [0u32; 10];
    let mut z3 = [0u32; 10];
    let mut a = [0u32; 10];
    let mut aa = [0u32; 10];
    let mut b = [0u32; 10];
    let mut bb = [0u32; 10];
    let mut c = [0u32; 10];
    let mut d = [0u32; 10];
    let mut e = [0u32; 10];
    let mut da = [0u32; 10];
    let mut cb = [0u32; 10];
    let mut k = [0u8; 32];

    /*
     * Points are encoded over exactly 32 bytes. Multipliers must fit in 32
     * bytes as well. RFC 7748 mandates clearing the high bit of the last byte.
     */
    if G.len() != 32 || kb.len() > 32 {
        return 0;
    }
    G[31] &= 0x7F;

    /*
     * Byteswap the point encoding (it is little-endian, the generic decoding
     * routine uses big-endian).
     */
    byteswap(G);

    /*
     * Decode the point ('u' coordinate). We use a synthetic modulus of value
     * 2^255 with br_i31_decode_mod(), then a conditional subtraction.
     */
    br_i31_zero(&mut b, 0x108);
    b[9] = 0x0080;
    br_i31_decode_mod(&mut a, G, 32, &b);
    a[0] = 0x107;
    let s = NOT(br_i31_sub(&mut a, &C255_P, 0));
    br_i31_sub(&mut a, &C255_P, s);

    /*
     * Initialise variables x1, x2, z2, x3, z3 (in Montgomery representation).
     */
    br_i31_montymul(&mut x1, &a, &C255_R2, &C255_P, P0I);
    x3 = x1;
    br_i31_zero(&mut z2, C255_P[0]);
    x2 = z2;
    x2[1] = 0x13000000;
    z3 = x2;

    /*
     * kb[] is in big-endian notation, but possibly shorter than k[].
     */
    let kblen = kb.len();
    k[32 - kblen..].copy_from_slice(kb);
    k[31] &= 0xF8;
    k[0] &= 0x7F;
    k[0] |= 0x40;

    let mut swap: u32 = 0;
    let mut i: i32 = 254;
    while i >= 0 {
        let kt = ((k[31 - (i >> 3) as usize] >> (i & 7)) & 1) as u32;
        swap ^= kt;
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = kt;

        c255_add(&mut a, &x2, &z2);
        let aval = a;
        c255_mul(&mut aa, &aval, &aval);
        c255_sub(&mut b, &x2, &z2);
        let bval = b;
        c255_mul(&mut bb, &bval, &bval);
        c255_sub(&mut e, &aa, &bb);
        c255_add(&mut c, &x3, &z3);
        c255_sub(&mut d, &x3, &z3);
        c255_mul(&mut da, &d, &a);
        c255_mul(&mut cb, &c, &b);

        c255_add(&mut x3, &da, &cb);
        let x3v = x3;
        c255_mul(&mut x3, &x3v, &x3v);
        c255_sub(&mut z3, &da, &cb);
        let z3v = z3;
        c255_mul(&mut z3, &z3v, &z3v);
        let z3v = z3;
        c255_mul(&mut z3, &z3v, &x1);
        c255_mul(&mut x2, &aa, &bb);
        c255_mul(&mut z2, &C255_A24, &e);
        let z2v = z2;
        c255_add(&mut z2, &z2v, &aa);
        let z2v = z2;
        c255_mul(&mut z2, &e, &z2v);

        i -= 1;
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);

    /*
     * Inverse z2 with a modular exponentiation (square-and-multiply). The
     * exponent (p-2) contains almost only ones.
     */
    a = z2;
    for _ in 0..15 {
        let av = a;
        c255_mul(&mut a, &av, &av);
        let av = a;
        c255_mul(&mut a, &av, &z2);
    }
    b = a;
    for _ in 0..14 {
        for _ in 0..16 {
            let bv = b;
            c255_mul(&mut b, &bv, &bv);
        }
        let bv = b;
        c255_mul(&mut b, &bv, &a);
    }
    let mut ii: i32 = 14;
    while ii >= 0 {
        let bv = b;
        c255_mul(&mut b, &bv, &bv);
        if (0xFFEB >> ii) & 1 != 0 {
            let bv = b;
            c255_mul(&mut b, &z2, &bv);
        }
        ii -= 1;
    }
    let bv = b;
    c255_mul(&mut b, &x2, &bv);

    /*
     * Convert from Montgomery representation by multiplying by 1.
     */
    br_i31_zero(&mut a, C255_P[0]);
    a[1] = 1;
    br_i31_montymul(&mut x2, &a, &b, &C255_P, P0I);

    br_i31_encode(&mut G[..32], 32, &x2);
    byteswap(G);
    1
}

fn api_mulgen(R: &mut [u8], x: &[u8], curve: i32) -> usize {
    let g = api_generator(curve);
    let glen = g.len();
    R[..glen].copy_from_slice(g);
    api_mul(&mut R[..glen], x, curve);
    glen
}

fn api_muladd(_A: &mut [u8], _B: Option<&[u8]>, _x: &[u8], _y: &[u8], _curve: i32) -> u32 {
    /*
     * Not implemented: used for ECDSA only, and there is no ECDSA over
     * Curve25519 (which uses EdDSA instead).
     */
    0
}

/// see bearssl_ec.h
pub static br_ec_c25519_i31: br_ec_impl = br_ec_impl {
    supported_curves: 0x20000000,
    generator: api_generator,
    order: api_order,
    xoff: api_xoff,
    mul: api_mul,
    mulgen: api_mulgen,
    muladd: api_muladd,
};
