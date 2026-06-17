/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Specialised P-256 (secp256r1) EC implementation `br_ec_p256_m31`
//! (`src/ec/ec_p256_m31.c`).
//!
//! Field elements are arrays of nine 30-bit words (little-endian). Values may
//! be slightly greater than the modulus but are always lower than twice it.
//! Relies on 31-bit multiplications (`MUL31`), with fast modular reduction
//! thanks to the special format of the field modulus.

use super::br_ec_impl;
use crate::inner::{EQ, MUL31, NEQ};

/*
 * Arithmetic right shift (the modulus reduction depends on the sign extension).
 */
#[inline(always)]
fn ARSH(x: u32, n: u32) -> u32 {
    ((x as i32) >> n) as u32
}

#[inline(always)]
fn ARSHW(x: u64, n: u32) -> u64 {
    ((x as i64) >> n) as u64
}

/*
 * Convert an integer from unsigned big-endian encoding to a sequence of 30-bit
 * words in little-endian order. The final "partial" word is returned.
 */
fn be8_to_le30(dst: &mut [u32], src: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    let mut di = 0usize;
    let mut len = src.len();
    while len > 0 {
        len -= 1;
        let b = src[len] as u32;
        if acc_len < 22 {
            acc |= b << acc_len;
            acc_len += 8;
        } else {
            dst[di] = (acc | (b << acc_len)) & 0x3FFFFFFF;
            di += 1;
            acc = b >> (30 - acc_len);
            acc_len -= 22;
        }
    }
    acc
}

/*
 * Convert an integer (30-bit words, little-endian) to unsigned big-endian
 * encoding. All `len` destination bytes are filled.
 */
fn le30_to_be8(dst: &mut [u8], len: usize, src: &[u32]) {
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    let mut si = 0usize;
    let mut len = len;
    while len > 0 {
        len -= 1;
        if acc_len < 8 {
            let w = src[si];
            si += 1;
            dst[len] = (acc | (w << acc_len)) as u8;
            acc = w >> (8 - acc_len);
            acc_len += 22;
        } else {
            dst[len] = acc as u8;
            acc >>= 8;
            acc_len -= 8;
        }
    }
}

/*
 * Multiply two integers (nine 30-bit words each, up to 2^270-1). Result over
 * 18 words of 30 bits.
 */
fn mul9(d: &mut [u32; 18], a: &[u32; 9], b: &[u32; 9]) {
    let mut t = [0u64; 17];

    t[0] = MUL31(a[0], b[0]);
    t[1] = MUL31(a[0], b[1]) + MUL31(a[1], b[0]);
    t[2] = MUL31(a[0], b[2]) + MUL31(a[1], b[1]) + MUL31(a[2], b[0]);
    t[3] = MUL31(a[0], b[3]) + MUL31(a[1], b[2]) + MUL31(a[2], b[1]) + MUL31(a[3], b[0]);
    t[4] = MUL31(a[0], b[4])
        + MUL31(a[1], b[3])
        + MUL31(a[2], b[2])
        + MUL31(a[3], b[1])
        + MUL31(a[4], b[0]);
    t[5] = MUL31(a[0], b[5])
        + MUL31(a[1], b[4])
        + MUL31(a[2], b[3])
        + MUL31(a[3], b[2])
        + MUL31(a[4], b[1])
        + MUL31(a[5], b[0]);
    t[6] = MUL31(a[0], b[6])
        + MUL31(a[1], b[5])
        + MUL31(a[2], b[4])
        + MUL31(a[3], b[3])
        + MUL31(a[4], b[2])
        + MUL31(a[5], b[1])
        + MUL31(a[6], b[0]);
    t[7] = MUL31(a[0], b[7])
        + MUL31(a[1], b[6])
        + MUL31(a[2], b[5])
        + MUL31(a[3], b[4])
        + MUL31(a[4], b[3])
        + MUL31(a[5], b[2])
        + MUL31(a[6], b[1])
        + MUL31(a[7], b[0]);
    t[8] = MUL31(a[0], b[8])
        + MUL31(a[1], b[7])
        + MUL31(a[2], b[6])
        + MUL31(a[3], b[5])
        + MUL31(a[4], b[4])
        + MUL31(a[5], b[3])
        + MUL31(a[6], b[2])
        + MUL31(a[7], b[1])
        + MUL31(a[8], b[0]);
    t[9] = MUL31(a[1], b[8])
        + MUL31(a[2], b[7])
        + MUL31(a[3], b[6])
        + MUL31(a[4], b[5])
        + MUL31(a[5], b[4])
        + MUL31(a[6], b[3])
        + MUL31(a[7], b[2])
        + MUL31(a[8], b[1]);
    t[10] = MUL31(a[2], b[8])
        + MUL31(a[3], b[7])
        + MUL31(a[4], b[6])
        + MUL31(a[5], b[5])
        + MUL31(a[6], b[4])
        + MUL31(a[7], b[3])
        + MUL31(a[8], b[2]);
    t[11] = MUL31(a[3], b[8])
        + MUL31(a[4], b[7])
        + MUL31(a[5], b[6])
        + MUL31(a[6], b[5])
        + MUL31(a[7], b[4])
        + MUL31(a[8], b[3]);
    t[12] = MUL31(a[4], b[8])
        + MUL31(a[5], b[7])
        + MUL31(a[6], b[6])
        + MUL31(a[7], b[5])
        + MUL31(a[8], b[4]);
    t[13] = MUL31(a[5], b[8]) + MUL31(a[6], b[7]) + MUL31(a[7], b[6]) + MUL31(a[8], b[5]);
    t[14] = MUL31(a[6], b[8]) + MUL31(a[7], b[7]) + MUL31(a[8], b[6]);
    t[15] = MUL31(a[7], b[8]) + MUL31(a[8], b[7]);
    t[16] = MUL31(a[8], b[8]);

    /* Propagate carries. */
    let mut cc: u64 = 0;
    for i in 0..17 {
        let w = t[i] + cc;
        d[i] = (w as u32) & 0x3FFFFFFF;
        cc = w >> 30;
    }
    d[17] = cc as u32;
}

/*
 * Square a 270-bit integer (nine 30-bit words). Result over 18 words.
 */
fn square9(d: &mut [u32; 18], a: &[u32; 9]) {
    let mut t = [0u64; 17];

    t[0] = MUL31(a[0], a[0]);
    t[1] = MUL31(a[0], a[1]) << 1;
    t[2] = MUL31(a[1], a[1]) + (MUL31(a[0], a[2]) << 1);
    t[3] = (MUL31(a[0], a[3]) + MUL31(a[1], a[2])) << 1;
    t[4] = MUL31(a[2], a[2]) + ((MUL31(a[0], a[4]) + MUL31(a[1], a[3])) << 1);
    t[5] = (MUL31(a[0], a[5]) + MUL31(a[1], a[4]) + MUL31(a[2], a[3])) << 1;
    t[6] = MUL31(a[3], a[3]) + ((MUL31(a[0], a[6]) + MUL31(a[1], a[5]) + MUL31(a[2], a[4])) << 1);
    t[7] = (MUL31(a[0], a[7]) + MUL31(a[1], a[6]) + MUL31(a[2], a[5]) + MUL31(a[3], a[4])) << 1;
    t[8] = MUL31(a[4], a[4])
        + ((MUL31(a[0], a[8]) + MUL31(a[1], a[7]) + MUL31(a[2], a[6]) + MUL31(a[3], a[5])) << 1);
    t[9] = (MUL31(a[1], a[8]) + MUL31(a[2], a[7]) + MUL31(a[3], a[6]) + MUL31(a[4], a[5])) << 1;
    t[10] = MUL31(a[5], a[5]) + ((MUL31(a[2], a[8]) + MUL31(a[3], a[7]) + MUL31(a[4], a[6])) << 1);
    t[11] = (MUL31(a[3], a[8]) + MUL31(a[4], a[7]) + MUL31(a[5], a[6])) << 1;
    t[12] = MUL31(a[6], a[6]) + ((MUL31(a[4], a[8]) + MUL31(a[5], a[7])) << 1);
    t[13] = (MUL31(a[5], a[8]) + MUL31(a[6], a[7])) << 1;
    t[14] = MUL31(a[7], a[7]) + (MUL31(a[6], a[8]) << 1);
    t[15] = MUL31(a[7], a[8]) << 1;
    t[16] = MUL31(a[8], a[8]);

    /* Propagate carries. */
    let mut cc: u64 = 0;
    for i in 0..17 {
        let w = t[i] + cc;
        d[i] = (w as u32) & 0x3FFFFFFF;
        cc = w >> 30;
    }
    d[17] = cc as u32;
}

/*
 * Base field modulus for P-256.
 */
static F256: [u32; 9] = [
    0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x0000003F, 0x00000000, 0x00000000, 0x00001000, 0x3FFFC000,
    0x0000FFFF,
];

/*
 * The 'b' curve equation coefficient for P-256.
 */
static P256_B: [u32; 9] = [
    0x27D2604B, 0x2F38F0F8, 0x053B0F63, 0x0741AC33, 0x1886BC65, 0x2EF555DA, 0x293E7B3E, 0x0D762A8E,
    0x00005AC6,
];

/*
 * Addition in the field. Source operands fit on 257 bits; output lower than
 * twice the modulus.
 */
fn add_f256(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    let mut w: u32 = 0;
    let mut cc: u32 = 0;
    for i in 0..9 {
        w = a[i].wrapping_add(b[i]).wrapping_add(cc);
        d[i] = w & 0x3FFFFFFF;
        cc = w >> 30;
    }
    w >>= 16;
    d[8] &= 0xFFFF;
    d[3] = d[3].wrapping_sub(w << 6);
    d[6] = d[6].wrapping_sub(w << 12);
    d[7] = d[7].wrapping_add(w << 14);
    cc = w;
    for i in 0..9 {
        w = d[i].wrapping_add(cc);
        d[i] = w & 0x3FFFFFFF;
        cc = ARSH(w, 30);
    }
}

/*
 * Subtraction in the field. Source operands smaller than twice the modulus;
 * result fulfils the same property.
 */
fn sub_f256(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    /* We really compute a - b + 2*p to make sure that the result is positive. */
    let mut w: u32;
    w = a[0].wrapping_sub(b[0]).wrapping_sub(0x00002);
    d[0] = w & 0x3FFFFFFF;
    w = a[1].wrapping_sub(b[1]).wrapping_add(ARSH(w, 30));
    d[1] = w & 0x3FFFFFFF;
    w = a[2].wrapping_sub(b[2]).wrapping_add(ARSH(w, 30));
    d[2] = w & 0x3FFFFFFF;
    w = a[3]
        .wrapping_sub(b[3])
        .wrapping_add(ARSH(w, 30))
        .wrapping_add(0x00080);
    d[3] = w & 0x3FFFFFFF;
    w = a[4].wrapping_sub(b[4]).wrapping_add(ARSH(w, 30));
    d[4] = w & 0x3FFFFFFF;
    w = a[5].wrapping_sub(b[5]).wrapping_add(ARSH(w, 30));
    d[5] = w & 0x3FFFFFFF;
    w = a[6]
        .wrapping_sub(b[6])
        .wrapping_add(ARSH(w, 30))
        .wrapping_add(0x02000);
    d[6] = w & 0x3FFFFFFF;
    w = a[7]
        .wrapping_sub(b[7])
        .wrapping_add(ARSH(w, 30))
        .wrapping_sub(0x08000);
    d[7] = w & 0x3FFFFFFF;
    w = a[8]
        .wrapping_sub(b[8])
        .wrapping_add(ARSH(w, 30))
        .wrapping_add(0x20000);
    d[8] = w & 0xFFFF;
    w >>= 16;
    d[8] &= 0xFFFF;
    d[3] = d[3].wrapping_sub(w << 6);
    d[6] = d[6].wrapping_sub(w << 12);
    d[7] = d[7].wrapping_add(w << 14);
    let mut cc = w;
    for i in 0..9 {
        w = d[i].wrapping_add(cc);
        d[i] = w & 0x3FFFFFFF;
        cc = ARSH(w, 30);
    }
}

/*
 * Multiplication in F256. Source operands less than twice the modulus.
 */
fn mul_f256(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    let mut t = [0u32; 18];
    let mut s = [0u64; 18];

    mul9(&mut t, a, b);

    for i in 0..18 {
        s[i] = t[i] as u64;
    }

    let mut i: i32 = 17;
    while i >= 9 {
        let iu = i as usize;
        let y = s[iu];
        s[iu - 1] = s[iu - 1].wrapping_add(ARSHW(y, 2));
        s[iu - 2] = s[iu - 2].wrapping_add((y << 28) & 0x3FFFFFFF);
        s[iu - 2] = s[iu - 2].wrapping_sub(ARSHW(y, 4));
        s[iu - 3] = s[iu - 3].wrapping_sub((y << 26) & 0x3FFFFFFF);
        s[iu - 5] = s[iu - 5].wrapping_sub(ARSHW(y, 10));
        s[iu - 6] = s[iu - 6].wrapping_sub((y << 20) & 0x3FFFFFFF);
        s[iu - 8] = s[iu - 8].wrapping_add(ARSHW(y, 16));
        s[iu - 9] = s[iu - 9].wrapping_add((y << 14) & 0x3FFFFFFF);
        i -= 1;
    }

    let mut cc: u64 = 0;
    let mut x: u64 = 0;
    for i in 0..9 {
        x = s[i].wrapping_add(cc);
        d[i] = (x as u32) & 0x3FFFFFFF;
        cc = ARSHW(x, 30);
    }

    cc = ARSHW(x, 16);
    d[8] &= 0xFFFF;

    let mut z = cc as u32;
    d[3] = d[3].wrapping_sub(z << 6);
    d[6] = d[6].wrapping_sub((z << 12) & 0x3FFFFFFF);
    d[7] = d[7].wrapping_sub(ARSH(z, 18));
    d[7] = d[7].wrapping_add((z << 14) & 0x3FFFFFFF);
    d[8] = d[8].wrapping_add(ARSH(z, 16));
    let c = z >> 31;
    d[0] = d[0].wrapping_sub(c);
    d[3] = d[3].wrapping_add(c << 6);
    d[6] = d[6].wrapping_add(c << 12);
    d[7] = d[7].wrapping_sub(c << 14);
    d[8] = d[8].wrapping_add(c << 16);
    for i in 0..9 {
        let w = d[i].wrapping_add(z);
        d[i] = w & 0x3FFFFFFF;
        z = ARSH(w, 30);
    }
}

/*
 * Square in F256. Source operand less than twice the modulus.
 */
fn square_f256(d: &mut [u32; 9], a: &[u32; 9]) {
    let mut t = [0u32; 18];
    let mut s = [0u64; 18];

    square9(&mut t, a);

    for i in 0..18 {
        s[i] = t[i] as u64;
    }

    let mut i: i32 = 17;
    while i >= 9 {
        let iu = i as usize;
        let y = s[iu];
        s[iu - 1] = s[iu - 1].wrapping_add(ARSHW(y, 2));
        s[iu - 2] = s[iu - 2].wrapping_add((y << 28) & 0x3FFFFFFF);
        s[iu - 2] = s[iu - 2].wrapping_sub(ARSHW(y, 4));
        s[iu - 3] = s[iu - 3].wrapping_sub((y << 26) & 0x3FFFFFFF);
        s[iu - 5] = s[iu - 5].wrapping_sub(ARSHW(y, 10));
        s[iu - 6] = s[iu - 6].wrapping_sub((y << 20) & 0x3FFFFFFF);
        s[iu - 8] = s[iu - 8].wrapping_add(ARSHW(y, 16));
        s[iu - 9] = s[iu - 9].wrapping_add((y << 14) & 0x3FFFFFFF);
        i -= 1;
    }

    let mut cc: u64 = 0;
    let mut x: u64 = 0;
    for i in 0..9 {
        x = s[i].wrapping_add(cc);
        d[i] = (x as u32) & 0x3FFFFFFF;
        cc = ARSHW(x, 30);
    }

    cc = ARSHW(x, 16);
    d[8] &= 0xFFFF;

    let mut z = cc as u32;
    d[3] = d[3].wrapping_sub(z << 6);
    d[6] = d[6].wrapping_sub((z << 12) & 0x3FFFFFFF);
    d[7] = d[7].wrapping_sub(ARSH(z, 18));
    d[7] = d[7].wrapping_add((z << 14) & 0x3FFFFFFF);
    d[8] = d[8].wrapping_add(ARSH(z, 16));
    let c = z >> 31;
    d[0] = d[0].wrapping_sub(c);
    d[3] = d[3].wrapping_add(c << 6);
    d[6] = d[6].wrapping_add(c << 12);
    d[7] = d[7].wrapping_sub(c << 14);
    d[8] = d[8].wrapping_add(c << 16);
    for i in 0..9 {
        let w = d[i].wrapping_add(z);
        d[i] = w & 0x3FFFFFFF;
        z = ARSH(w, 30);
    }
}

/*
 * "Final reduction" in F256. Source value less than twice the modulus. If not
 * lower than the modulus, subtract it and return 1; otherwise leave untouched
 * and return 0.
 */
fn reduce_final_f256(d: &mut [u32; 9]) -> u32 {
    let mut t = [0u32; 9];
    let mut cc: u32 = 0;
    for i in 0..9 {
        let w = d[i].wrapping_sub(F256[i]).wrapping_sub(cc);
        cc = w >> 31;
        t[i] = w & 0x3FFFFFFF;
    }
    cc ^= 1;
    let m = cc.wrapping_neg();
    for i in 0..9 {
        d[i] ^= m & (d[i] ^ t[i]);
    }
    cc
}

/*
 * Jacobian coordinates for a point in P-256.
 */
#[derive(Clone, Copy)]
struct p256_jacobian {
    x: [u32; 9],
    y: [u32; 9],
    z: [u32; 9],
}

impl p256_jacobian {
    fn zeroed() -> Self {
        p256_jacobian {
            x: [0; 9],
            y: [0; 9],
            z: [0; 9],
        }
    }
}

/// Constant-time conditional copy of a Jacobian point (`CCOPY`).
fn ccopy_point(ctl: u32, dst: &mut p256_jacobian, src: &p256_jacobian) {
    let m = ctl.wrapping_neg();
    for i in 0..9 {
        dst.x[i] ^= m & (dst.x[i] ^ src.x[i]);
        dst.y[i] ^= m & (dst.y[i] ^ src.y[i]);
        dst.z[i] ^= m & (dst.z[i] ^ src.z[i]);
    }
}

/*
 * Convert a point to affine coordinates.
 */
fn p256_to_affine(P: &mut p256_jacobian) {
    let mut t1 = [0u32; 9];
    let mut t2 = [0u32; 9];

    /* z^(2^31-1) via square-and-multiply. */
    t1.copy_from_slice(&P.z);
    for _ in 0..30 {
        let t1v = t1;
        square_f256(&mut t1, &t1v);
        let t1v = t1;
        mul_f256(&mut t1, &t1v, &P.z);
    }

    t2.copy_from_slice(&P.z);
    for i in 1..256 {
        let t2v = t2;
        square_f256(&mut t2, &t2v);
        match i {
            31 | 190 | 221 | 252 => {
                let t2v = t2;
                mul_f256(&mut t2, &t2v, &t1);
            }
            63 | 253 | 255 => {
                let t2v = t2;
                mul_f256(&mut t2, &t2v, &P.z);
            }
            _ => {}
        }
    }

    /* Multiply x by 1/z^2 and y by 1/z^3. */
    let t2v = t2;
    mul_f256(&mut t1, &t2v, &t2v);
    let px = P.x;
    let t1v = t1;
    mul_f256(&mut P.x, &t1v, &px);
    let t1v = t1;
    mul_f256(&mut t1, &t1v, &t2);
    let py = P.y;
    let t1v = t1;
    mul_f256(&mut P.y, &t1v, &py);
    reduce_final_f256(&mut P.x);
    reduce_final_f256(&mut P.y);

    /* Multiply z by 1/z. */
    let pz = P.z;
    mul_f256(&mut P.z, &pz, &t2);
    reduce_final_f256(&mut P.z);
}

/*
 * Double a point in P-256. Works for all valid points, including infinity.
 */
fn p256_double(Q: &mut p256_jacobian) {
    let mut t1 = [0u32; 9];
    let mut t2 = [0u32; 9];
    let mut t3 = [0u32; 9];
    let mut t4 = [0u32; 9];

    /* z^2 in t1. */
    square_f256(&mut t1, &Q.z);

    /* x-z^2 in t2 ... wait: add gives x+z^2 in t2, sub gives x-z^2 in t1. */
    add_f256(&mut t2, &Q.x, &t1);
    let t1v = t1;
    sub_f256(&mut t1, &Q.x, &t1v);

    /* 3*(x+z^2)*(x-z^2) in t1. */
    mul_f256(&mut t3, &t1, &t2);
    let t3v = t3;
    add_f256(&mut t1, &t3v, &t3v);
    let t1v = t1;
    add_f256(&mut t1, &t3, &t1v);

    /* 4*x*y^2 (in t2) and 2*y^2 (in t3). */
    square_f256(&mut t3, &Q.y);
    let t3v = t3;
    add_f256(&mut t3, &t3v, &t3v);
    mul_f256(&mut t2, &Q.x, &t3);
    let t2v = t2;
    add_f256(&mut t2, &t2v, &t2v);

    /* x' = m^2 - 2*s. */
    square_f256(&mut Q.x, &t1);
    let qx = Q.x;
    sub_f256(&mut Q.x, &qx, &t2);
    let qx = Q.x;
    sub_f256(&mut Q.x, &qx, &t2);

    /* z' = 2*y*z. */
    mul_f256(&mut t4, &Q.y, &Q.z);
    add_f256(&mut Q.z, &t4, &t4);

    /* y' = m*(s - x') - 8*y^4. (2*y^2 already in t3.) */
    let t2v = t2;
    sub_f256(&mut t2, &t2v, &Q.x);
    mul_f256(&mut Q.y, &t1, &t2);
    square_f256(&mut t4, &t3);
    let t4v = t4;
    add_f256(&mut t4, &t4v, &t4v);
    let qy = Q.y;
    sub_f256(&mut Q.y, &qy, &t4);
}

/*
 * Add point P2 to point P1. See the C source for the exact error semantics.
 */
fn p256_add(P1: &mut p256_jacobian, P2: &p256_jacobian) -> u32 {
    let mut t1 = [0u32; 9];
    let mut t2 = [0u32; 9];
    let mut t3 = [0u32; 9];
    let mut t4 = [0u32; 9];
    let mut t5 = [0u32; 9];
    let mut t6 = [0u32; 9];
    let mut t7 = [0u32; 9];

    /* u1 = x1*z2^2 (in t1) and s1 = y1*z2^3 (in t3). */
    square_f256(&mut t3, &P2.z);
    mul_f256(&mut t1, &P1.x, &t3);
    mul_f256(&mut t4, &P2.z, &t3);
    mul_f256(&mut t3, &P1.y, &t4);

    /* u2 = x2*z1^2 (in t2) and s2 = y2*z1^3 (in t4). */
    square_f256(&mut t4, &P1.z);
    mul_f256(&mut t2, &P2.x, &t4);
    mul_f256(&mut t5, &P1.z, &t4);
    mul_f256(&mut t4, &P2.y, &t5);

    /* h = u2 - u1 (in t2) and r = s2 - s1 (in t4). */
    let t2v = t2;
    sub_f256(&mut t2, &t2v, &t1);
    let t4v = t4;
    sub_f256(&mut t4, &t4v, &t3);
    reduce_final_f256(&mut t4);
    let mut ret: u32 = 0;
    for i in 0..9 {
        ret |= t4[i];
    }
    ret = (ret | ret.wrapping_neg()) >> 31;

    /* u1*h^2 (in t6) and h^3 (in t5). */
    square_f256(&mut t7, &t2);
    mul_f256(&mut t6, &t1, &t7);
    mul_f256(&mut t5, &t7, &t2);

    /* x3 = r^2 - h^3 - 2*u1*h^2. */
    square_f256(&mut P1.x, &t4);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t5);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t6);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t6);

    /* y3 = r*(u1*h^2 - x3) - s1*h^3. */
    let t6v = t6;
    sub_f256(&mut t6, &t6v, &P1.x);
    mul_f256(&mut P1.y, &t4, &t6);
    mul_f256(&mut t1, &t5, &t3);
    let py = P1.y;
    sub_f256(&mut P1.y, &py, &t1);

    /* z3 = h*z1*z2. */
    mul_f256(&mut t1, &P1.z, &P2.z);
    let t1v = t1;
    mul_f256(&mut P1.z, &t1v, &t2);

    ret
}

/*
 * Add point P2 (non-zero, affine) to point P1.
 */
fn p256_add_mixed(P1: &mut p256_jacobian, P2: &p256_jacobian) -> u32 {
    let mut t1 = [0u32; 9];
    let mut t2 = [0u32; 9];
    let mut t3 = [0u32; 9];
    let mut t4 = [0u32; 9];
    let mut t5 = [0u32; 9];
    let mut t6 = [0u32; 9];
    let mut t7 = [0u32; 9];

    /* u1 = x1 (in t1) and s1 = y1 (in t3). */
    t1.copy_from_slice(&P1.x);
    t3.copy_from_slice(&P1.y);

    /* u2 = x2*z1^2 (in t2) and s2 = y2*z1^3 (in t4). */
    square_f256(&mut t4, &P1.z);
    mul_f256(&mut t2, &P2.x, &t4);
    mul_f256(&mut t5, &P1.z, &t4);
    mul_f256(&mut t4, &P2.y, &t5);

    /* h = u2 - u1 (in t2) and r = s2 - s1 (in t4). */
    let t2v = t2;
    sub_f256(&mut t2, &t2v, &t1);
    let t4v = t4;
    sub_f256(&mut t4, &t4v, &t3);
    reduce_final_f256(&mut t4);
    let mut ret: u32 = 0;
    for i in 0..9 {
        ret |= t4[i];
    }
    ret = (ret | ret.wrapping_neg()) >> 31;

    /* u1*h^2 (in t6) and h^3 (in t5). */
    square_f256(&mut t7, &t2);
    mul_f256(&mut t6, &t1, &t7);
    mul_f256(&mut t5, &t7, &t2);

    /* x3 = r^2 - h^3 - 2*u1*h^2. */
    square_f256(&mut P1.x, &t4);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t5);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t6);
    let px = P1.x;
    sub_f256(&mut P1.x, &px, &t6);

    /* y3 = r*(u1*h^2 - x3) - s1*h^3. */
    let t6v = t6;
    sub_f256(&mut t6, &t6v, &P1.x);
    mul_f256(&mut P1.y, &t4, &t6);
    mul_f256(&mut t1, &t5, &t3);
    let py = P1.y;
    sub_f256(&mut P1.y, &py, &t1);

    /* z3 = h*z1. */
    let pz = P1.z;
    mul_f256(&mut P1.z, &pz, &t2);

    ret
}

/*
 * Decode a P-256 point. Does not support the point at infinity. Returns 0 if
 * invalid, 1 otherwise.
 */
fn p256_decode(P: &mut p256_jacobian, src: &[u8]) -> u32 {
    let mut tx = [0u32; 9];
    let mut ty = [0u32; 9];
    let mut t1 = [0u32; 9];
    let mut t2 = [0u32; 9];

    if src.len() != 65 {
        return 0;
    }

    /* First byte must be 0x04 (uncompressed). */
    let mut bad = NEQ(src[0] as u32, 0x04);

    /* Decode the coordinates; both must be lower than the modulus. */
    tx[8] = be8_to_le30(&mut tx, &src[1..33]);
    ty[8] = be8_to_le30(&mut ty, &src[33..65]);
    bad |= reduce_final_f256(&mut tx);
    bad |= reduce_final_f256(&mut ty);

    /* Check curve equation. */
    square_f256(&mut t1, &tx);
    let t1v = t1;
    mul_f256(&mut t1, &tx, &t1v);
    square_f256(&mut t2, &ty);
    let t1v = t1;
    sub_f256(&mut t1, &t1v, &tx);
    let t1v = t1;
    sub_f256(&mut t1, &t1v, &tx);
    let t1v = t1;
    sub_f256(&mut t1, &t1v, &tx);
    let t1v = t1;
    add_f256(&mut t1, &t1v, &P256_B);
    let t1v = t1;
    sub_f256(&mut t1, &t1v, &t2);
    reduce_final_f256(&mut t1);
    for i in 0..9 {
        bad |= t1[i];
    }

    /* Copy coordinates to the point structure. */
    P.x.copy_from_slice(&tx);
    P.y.copy_from_slice(&ty);
    for w in P.z.iter_mut() {
        *w = 0;
    }
    P.z[0] = 1;
    EQ(bad, 0)
}

/*
 * Encode a point. Assumes valid, affine, not infinity.
 */
fn p256_encode(dst: &mut [u8], P: &p256_jacobian) {
    dst[0] = 0x04;
    le30_to_be8(&mut dst[1..33], 32, &P.x);
    le30_to_be8(&mut dst[33..65], 32, &P.y);
}

/*
 * Multiply a curve point by an integer (lower than the curve order); base point
 * not infinity.
 */
fn p256_mul(P: &mut p256_jacobian, x: &[u8]) {
    let mut P2 = *P;
    p256_double(&mut P2);
    let mut P3 = *P;
    p256_add(&mut P3, &P2);

    let mut Q = p256_jacobian::zeroed();
    let mut qz: u32 = 1;
    for &xb in x.iter() {
        let mut k: i32 = 6;
        while k >= 0 {
            p256_double(&mut Q);
            p256_double(&mut Q);
            let mut T = *P;
            let mut U = Q;
            let bits = ((xb as u32) >> k) & 3;
            let bnz = NEQ(bits, 0);
            ccopy_point(EQ(bits, 2), &mut T, &P2);
            ccopy_point(EQ(bits, 3), &mut T, &P3);
            p256_add(&mut U, &T);
            ccopy_point(bnz & qz, &mut Q, &T);
            ccopy_point(bnz & !qz, &mut Q, &U);
            qz &= !bnz;
            k -= 2;
        }
    }
    *P = Q;
}

/*
 * Precomputed window: k*G for k = 1..15. X and Y over 9 words of 30 bits each.
 */
static Gwin: [[u32; 18]; 15] = [
    [
        0x1898C296, 0x1284E517, 0x1EB33A0F, 0x00DF604B, 0x2440F277, 0x339B958E, 0x04247F8B,
        0x347CB84B, 0x00006B17, 0x37BF51F5, 0x2ED901A0, 0x3315ECEC, 0x338CD5DA, 0x0F9E162B,
        0x1FAD29F0, 0x27F9B8EE, 0x10B8BF86, 0x00004FE3,
    ],
    [
        0x07669978, 0x182D23F1, 0x3F21B35A, 0x225A789D, 0x351AC3C0, 0x08E00C12, 0x34F7E8A5,
        0x1EC62340, 0x00007CF2, 0x227873D1, 0x3812DE74, 0x0E982299, 0x1F6B798F, 0x3430DBBA,
        0x366B1A7D, 0x2D040293, 0x154436E3, 0x00000777,
    ],
    [
        0x06E7FD6C, 0x2D05986F, 0x3ADA985F, 0x31ADC87B, 0x0BF165E6, 0x1FBE5475, 0x30A44C8F,
        0x3934698C, 0x00005ECB, 0x227D5032, 0x29E6C49E, 0x04FB83D9, 0x0AAC0D8E, 0x24A2ECD8,
        0x2C1B3869, 0x0FF7E374, 0x19031266, 0x00008734,
    ],
    [
        0x2B030852, 0x024C0911, 0x05596EF5, 0x07F8B6DE, 0x262BD003, 0x3779967B, 0x08FBBA02,
        0x128D4CB4, 0x0000E253, 0x184ED8C6, 0x310B08FC, 0x30EE0055, 0x3F25B0FC, 0x062D764E,
        0x3FB97F6A, 0x33CC719D, 0x15D69318, 0x0000E0F1,
    ],
    [
        0x03D033ED, 0x05552837, 0x35BE5242, 0x2320BF47, 0x268FDFEF, 0x13215821, 0x140D2D78,
        0x02DE9454, 0x00005159, 0x3DA16DA4, 0x0742ED13, 0x0D80888D, 0x004BC035, 0x0A79260D,
        0x06FCDAFE, 0x2727D8AE, 0x1F6A2412, 0x0000E0C1,
    ],
    [
        0x3C2291A9, 0x1AC2ABA4, 0x3B215B4C, 0x131D037A, 0x17DDE302, 0x0C90B2E2, 0x0602C92D,
        0x05CA9DA9, 0x0000B01A, 0x0FC77FE2, 0x35F1214E, 0x07E16BDF, 0x003DDC07, 0x2703791C,
        0x3038B7EE, 0x3DAD56FE, 0x041D0C8D, 0x0000E85C,
    ],
    [
        0x3187B2A3, 0x0018A1C0, 0x00FEF5B3, 0x3E7E2E2A, 0x01FB607E, 0x2CC199F0, 0x37B4625B,
        0x0EDBE82F, 0x00008E53, 0x01F400B4, 0x15786A1B, 0x3041B21C, 0x31CD8CF2, 0x35900053,
        0x1A7E0E9B, 0x318366D0, 0x076F780C, 0x000073EB,
    ],
    [
        0x1B6FB393, 0x13767707, 0x3CE97DBB, 0x348E2603, 0x354CADC1, 0x09D0B4EA, 0x1B053404,
        0x1DE76FBA, 0x000062D9, 0x0F09957E, 0x295029A8, 0x3E76A78D, 0x3B547DAE, 0x27CEE0A2,
        0x0575DC45, 0x1D8244FF, 0x332F647A, 0x0000AD5A,
    ],
    [
        0x10949EE0, 0x1E7A292E, 0x06DF8B3D, 0x02B2E30B, 0x31F8729E, 0x24E35475, 0x30B71878,
        0x35EDBFB7, 0x0000EA68, 0x0DD048FA, 0x21688929, 0x0DE823FE, 0x1C53FAA9, 0x0EA0C84D,
        0x052A592A, 0x1FCE7870, 0x11325CB2, 0x00002A27,
    ],
    [
        0x04C5723F, 0x30D81A50, 0x048306E4, 0x329B11C7, 0x223FB545, 0x085347A8, 0x2993E591,
        0x1B5ACA8E, 0x0000CEF6, 0x04AF0773, 0x28D2EEA9, 0x2751EEEC, 0x037B4A7F, 0x3B4C1059,
        0x08F37674, 0x2AE906E1, 0x18A88A6A, 0x00008786,
    ],
    [
        0x34BC21D1, 0x0CCE474D, 0x15048BF4, 0x1D0BB409, 0x021CDA16, 0x20DE76C3, 0x34C59063,
        0x04EDE20E, 0x00003ED1, 0x282A3740, 0x0BE3BBF3, 0x29889DAE, 0x03413697, 0x34C68A09,
        0x210EBE93, 0x0C8A224C, 0x0826B331, 0x00009099,
    ],
    [
        0x0624E3C4, 0x140317BA, 0x2F82C99D, 0x260C0A2C, 0x25D55179, 0x194DCC83, 0x3D95E462,
        0x356F6A05, 0x0000741D, 0x0D4481D3, 0x2657FC8B, 0x1BA5CA71, 0x3AE44B0D, 0x07B1548E,
        0x0E0D5522, 0x05FDC567, 0x2D1AA70E, 0x00000770,
    ],
    [
        0x06072C01, 0x23857675, 0x1EAD58A9, 0x0B8A12D9, 0x1EE2FC79, 0x0177CB61, 0x0495A618,
        0x20DEB82B, 0x0000177C, 0x2FC7BFD8, 0x310EEF8B, 0x1FB4DF39, 0x3B8530E8, 0x0F4E7226,
        0x0246B6D0, 0x2A558A24, 0x163353AF, 0x000063BB,
    ],
    [
        0x24D2920B, 0x1C249DCC, 0x2069C5E5, 0x09AB2F9E, 0x36DF3CF1, 0x1991FD0C, 0x062B97A7,
        0x1E80070E, 0x000054E7, 0x20D0B375, 0x2E9F20BD, 0x35090081, 0x1C7A9DDC, 0x22E7C371,
        0x087E3016, 0x03175421, 0x3C6ECA7D, 0x0000F599,
    ],
    [
        0x259B9D5F, 0x0D9A318F, 0x23A0EF16, 0x00EBE4B7, 0x088265AE, 0x2CDE2666, 0x2BAE7ADF,
        0x1371A5C6, 0x0000F045, 0x0D034F36, 0x1F967378, 0x1B5FA3F4, 0x0EC8739D, 0x1643E62A,
        0x1653947E, 0x22D1F4E6, 0x0FB8D64B, 0x0000B5B9,
    ],
];

/*
 * Lookup one of the Gwin[] values, by index. Constant-time.
 */
fn lookup_Gwin(T: &mut p256_jacobian, idx: u32) {
    let mut xy = [0u32; 18];
    for k in 0..15u32 {
        let m = EQ(idx, k + 1).wrapping_neg();
        for u in 0..18 {
            xy[u] |= m & Gwin[k as usize][u];
        }
    }
    T.x.copy_from_slice(&xy[0..9]);
    T.y.copy_from_slice(&xy[9..18]);
    for w in T.z.iter_mut() {
        *w = 0;
    }
    T.z[0] = 1;
}

/*
 * Multiply the generator by an integer (non-zero, lower than the curve order).
 */
fn p256_mulgen(P: &mut p256_jacobian, x: &[u8]) {
    let mut Q = p256_jacobian::zeroed();
    let mut qz: u32 = 1;
    for &xb0 in x.iter() {
        let mut bx = xb0 as u32;
        for _ in 0..2 {
            p256_double(&mut Q);
            p256_double(&mut Q);
            p256_double(&mut Q);
            p256_double(&mut Q);
            let bits = (bx >> 4) & 0x0F;
            let bnz = NEQ(bits, 0);
            let mut T = p256_jacobian::zeroed();
            lookup_Gwin(&mut T, bits);
            let mut U = Q;
            p256_add_mixed(&mut U, &T);
            ccopy_point(bnz & qz, &mut Q, &T);
            ccopy_point(bnz & !qz, &mut Q, &U);
            qz &= !bnz;
            bx <<= 4;
        }
    }
    *P = Q;
}

static P256_G: [u8; 65] = [
    0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
    0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
    0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
    0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
    0xF5,
];

static P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

fn api_generator(_curve: i32) -> &'static [u8] {
    &P256_G
}

fn api_order(_curve: i32) -> &'static [u8] {
    &P256_N
}

fn api_xoff(_curve: i32, len: &mut usize) -> usize {
    *len = 32;
    1
}

fn api_mul(G: &mut [u8], x: &[u8], _curve: i32) -> u32 {
    if G.len() != 65 {
        return 0;
    }
    let mut P = p256_jacobian::zeroed();
    let r = p256_decode(&mut P, G);
    p256_mul(&mut P, x);
    p256_to_affine(&mut P);
    p256_encode(G, &P);
    r
}

fn api_mulgen(R: &mut [u8], x: &[u8], _curve: i32) -> usize {
    let mut P = p256_jacobian::zeroed();
    p256_mulgen(&mut P, x);
    p256_to_affine(&mut P);
    p256_encode(R, &P);
    65
}

fn api_muladd(A: &mut [u8], B: Option<&[u8]>, x: &[u8], y: &[u8], _curve: i32) -> u32 {
    if A.len() != 65 {
        return 0;
    }
    let mut P = p256_jacobian::zeroed();
    let mut Q = p256_jacobian::zeroed();
    let mut r = p256_decode(&mut P, A);
    p256_mul(&mut P, x);
    match B {
        None => {
            p256_mulgen(&mut Q, y);
        }
        Some(b) => {
            r &= p256_decode(&mut Q, b);
            p256_mul(&mut Q, y);
        }
    }

    /* The final addition may fail in case both points are equal. */
    let t = p256_add(&mut P, &Q);
    reduce_final_f256(&mut P.z);
    let mut z: u32 = 0;
    for i in 0..9 {
        z |= P.z[i];
    }
    z = EQ(z, 0);
    p256_double(&mut Q);

    ccopy_point(z & !t, &mut P, &Q);
    p256_to_affine(&mut P);
    p256_encode(A, &P);
    r &= !(z & t);
    r
}

/// see bearssl_ec.h
pub static br_ec_p256_m31: br_ec_impl = br_ec_impl {
    supported_curves: 0x00800000,
    generator: api_generator,
    order: api_order,
    xoff: api_xoff,
    mul: api_mul,
    mulgen: api_mulgen,
    muladd: api_muladd,
};
