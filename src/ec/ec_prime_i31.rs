/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Generic prime-curve EC implementation `br_ec_prime_i31`
//! (`src/ec/ec_prime_i31.c`).
//!
//! Internally uses the generic `i31` modular-integer code (31-bit words). It
//! supports secp256r1, secp384r1 and secp521r1 (NIST P-256, P-384, P-521).
//!
//! Point arithmetic is driven by a tiny bytecode interpreter ([`run_code`]) with
//! a dozen registers and six operations (MSET/MADD/MSUB/MMUL/MINV/MTZ), exactly
//! as in the C source.

use super::{
    br_ec_curve_def, br_ec_impl, br_secp256r1, br_secp384r1, br_secp521r1, BR_EC_secp256r1,
    BR_EC_secp384r1, BR_EC_secp521r1, BR_MAX_EC_SIZE,
};
use crate::inner::{EQ, NEQ, NOT};
use crate::int::ccopy_words;
use crate::int::{
    br_i31_add, br_i31_decode_mod, br_i31_encode, br_i31_iszero, br_i31_modpow, br_i31_montymul,
    br_i31_sub,
};

/*
 * Parameters for supported curves (field modulus, and 'b' equation
 * parameter; both values use the 'i31' format, and 'b' is in Montgomery
 * representation).
 */

static P256_P: [u32; 10] = [
    0x00000108, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x00000007, 0x00000000, 0x00000000, 0x00000040,
    0x7FFFFF80, 0x000000FF,
];

static P256_R2: [u32; 10] = [
    0x00000108, 0x00014000, 0x00018000, 0x00000000, 0x7FF40000, 0x7FEFFFFF, 0x7FF7FFFF, 0x7FAFFFFF,
    0x005FFFFF, 0x00000000,
];

static P256_B: [u32; 10] = [
    0x00000108, 0x6FEE1803, 0x6229C4BD, 0x21B139BE, 0x327150AA, 0x3567802E, 0x3F7212ED, 0x012E4355,
    0x782DD38D, 0x0000000E,
];

static P384_P: [u32; 14] = [
    0x0000018C, 0x7FFFFFFF, 0x00000001, 0x00000000, 0x7FFFFFF8, 0x7FFFFFEF, 0x7FFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x00000FFF,
];

static P384_R2: [u32; 14] = [
    0x0000018C, 0x00000000, 0x00000080, 0x7FFFFE00, 0x000001FF, 0x00000800, 0x00000000, 0x7FFFE000,
    0x00001FFF, 0x00008000, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
];

static P384_B: [u32; 14] = [
    0x0000018C, 0x6E666840, 0x070D0392, 0x5D810231, 0x7651D50C, 0x17E218D6, 0x1B192002, 0x44EFE441,
    0x3A524E2B, 0x2719BA5F, 0x41F02209, 0x36C5643E, 0x5813EFFE, 0x000008A5,
];

static P521_P: [u32; 18] = [
    0x00000219, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0x01FFFFFF,
];

static P521_R2: [u32; 18] = [
    0x00000219, 0x00001000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
];

static P521_B: [u32; 18] = [
    0x00000219, 0x540FC00A, 0x228FEA35, 0x2C34F1EF, 0x67BF107A, 0x46FC1CD5, 0x1605E9DD, 0x6937B165,
    0x272A3D8F, 0x42785586, 0x44C8C778, 0x15F3B8B4, 0x64B73366, 0x03BA8B69, 0x0D05B42A, 0x21F929A2,
    0x2C31C393, 0x00654FAE,
];

struct curve_params {
    p: &'static [u32],
    b: &'static [u32],
    R2: &'static [u32],
    p0i: u32,
    point_len: usize,
}

fn id_to_curve(curve: i32) -> curve_params {
    match curve {
        BR_EC_secp256r1 => curve_params {
            p: &P256_P,
            b: &P256_B,
            R2: &P256_R2,
            p0i: 0x00000001,
            point_len: 65,
        },
        BR_EC_secp384r1 => curve_params {
            p: &P384_P,
            b: &P384_B,
            R2: &P384_R2,
            p0i: 0x00000001,
            point_len: 97,
        },
        // BR_EC_secp521r1 and anything else in range maps to P-521.
        _ => curve_params {
            p: &P521_P,
            b: &P521_B,
            R2: &P521_R2,
            p0i: 0x00000001,
            point_len: 133,
        },
    }
}

/// `I31_LEN = (BR_MAX_EC_SIZE + 61) / 31` words per coordinate.
const I31_LEN: usize = (BR_MAX_EC_SIZE + 61) / 31;

/*
 * A point in Jacobian coordinates: three values x, y, z (in Montgomery
 * representation). Affine coordinates are X = x/z^2, Y = y/z^3; for the point
 * at infinity, z = 0.
 */
#[derive(Clone)]
struct jacobian {
    c: [[u32; I31_LEN]; 3],
}

impl jacobian {
    fn zeroed() -> Self {
        jacobian {
            c: [[0u32; I31_LEN]; 3],
        }
    }
}

/*
 * Custom interpreter opcodes (see the C source for the formulas). Each is a
 * 16-bit word encoding operation, destination and operands.
 */
const fn MSET(d: u16, a: u16) -> u16 {
    0x0000 + (d << 8) + (a << 4)
}
const fn MADD(d: u16, a: u16) -> u16 {
    0x1000 + (d << 8) + (a << 4)
}
const fn MSUB(d: u16, a: u16) -> u16 {
    0x2000 + (d << 8) + (a << 4)
}
const fn MMUL(d: u16, a: u16, b: u16) -> u16 {
    0x3000 + (d << 8) + (a << 4) + b
}
const fn MINV(d: u16, a: u16, b: u16) -> u16 {
    0x4000 + (d << 8) + (a << 4) + b
}
const fn MTZ(d: u16) -> u16 {
    0x5000 + (d << 8)
}
const ENDCODE: u16 = 0;

// Registers for the input operands.
const P1x: u16 = 0;
const P1y: u16 = 1;
const P1z: u16 = 2;
const P2x: u16 = 3;
const P2y: u16 = 4;
const P2z: u16 = 5;

// Alternate names for the first input operand.
const Px: u16 = 0;
const Py: u16 = 1;
const Pz: u16 = 2;

// Temporaries.
const t1: u16 = 6;
const t2: u16 = 7;
const t3: u16 = 8;
const t4: u16 = 9;
const t5: u16 = 10;
const t6: u16 = 11;
const t7: u16 = 12;

/*
 * Doubling formulas (cost: 8 multiplications). See the C source.
 */
static code_double: &[u16] = &[
    MMUL(t1, Pz, Pz),
    MSET(t2, Px),
    MSUB(t2, t1),
    MADD(t1, Px),
    MMUL(t3, t1, t2),
    MSET(t1, t3),
    MADD(t1, t3),
    MADD(t1, t3),
    MMUL(t3, Py, Py),
    MADD(t3, t3),
    MMUL(t2, Px, t3),
    MADD(t2, t2),
    MMUL(Px, t1, t1),
    MSUB(Px, t2),
    MSUB(Px, t2),
    MMUL(t4, Py, Pz),
    MSET(Pz, t4),
    MADD(Pz, t4),
    MSUB(t2, Px),
    MMUL(Py, t1, t2),
    MMUL(t4, t3, t3),
    MSUB(Py, t4),
    MSUB(Py, t4),
    ENDCODE,
];

/*
 * Addition formulas (cost: 16 multiplications). See the C source.
 */
static code_add: &[u16] = &[
    MMUL(t3, P2z, P2z),
    MMUL(t1, P1x, t3),
    MMUL(t4, P2z, t3),
    MMUL(t3, P1y, t4),
    MMUL(t4, P1z, P1z),
    MMUL(t2, P2x, t4),
    MMUL(t5, P1z, t4),
    MMUL(t4, P2y, t5),
    MSUB(t2, t1),
    MSUB(t4, t3),
    MTZ(t4),
    MMUL(t7, t2, t2),
    MMUL(t6, t1, t7),
    MMUL(t5, t7, t2),
    MMUL(P1x, t4, t4),
    MSUB(P1x, t5),
    MSUB(P1x, t6),
    MSUB(P1x, t6),
    MSUB(t6, P1x),
    MMUL(P1y, t4, t6),
    MMUL(t1, t5, t3),
    MSUB(P1y, t1),
    MMUL(t1, P1z, P2z),
    MMUL(P1z, t1, t2),
    ENDCODE,
];

/*
 * Check that the point is on the curve. Assumes that x and y have been freshly
 * decoded in P1 (not converted to Montgomery yet), and P2x/P2y/P2z are set to
 * R^2, b*R and 1 respectively.
 */
static code_check: &[u16] = &[
    MMUL(t1, P1x, P2x),
    MMUL(t2, P1y, P2x),
    MSET(P1x, t1),
    MSET(P1y, t2),
    MMUL(t2, P1x, P1x),
    MMUL(t1, P1x, t2),
    MSUB(t1, P1x),
    MSUB(t1, P1x),
    MSUB(t1, P1x),
    MADD(t1, P2y),
    MMUL(t2, P1y, P1y),
    MSUB(t1, t2),
    MTZ(t1),
    MMUL(P1z, P2x, P2z),
    ENDCODE,
];

/*
 * Conversion back to affine coordinates. Assumes that the z coordinate of P2 is
 * set to 1 (not in Montgomery representation).
 */
static code_affine: &[u16] = &[
    MSET(t1, P1z),
    MMUL(t2, P1z, P1z),
    MMUL(t3, P1z, t2),
    MMUL(t2, t3, P2z),
    MINV(t2, t3, t4),
    MSET(t3, P1y),
    MMUL(P1y, t2, t3),
    MMUL(t3, t2, t1),
    MSET(t2, P1x),
    MMUL(P1x, t2, t3),
    ENDCODE,
];

fn run_code(P1: &mut jacobian, P2: &jacobian, cc: &curve_params, code: &[u16]) -> u32 {
    let mut r: u32 = 1;
    let mut t = [[0u32; I31_LEN]; 13];

    /*
     * Copy the two operands into the dedicated registers.
     */
    t[P1x as usize] = P1.c[0];
    t[(P1x + 1) as usize] = P1.c[1];
    t[(P1x + 2) as usize] = P1.c[2];
    t[P2x as usize] = P2.c[0];
    t[(P2x + 1) as usize] = P2.c[1];
    t[(P2x + 2) as usize] = P2.c[2];

    /*
     * Run formulas.
     */
    let mut u = 0usize;
    loop {
        let opw = code[u];
        if opw == 0 {
            break;
        }
        let d = ((opw >> 8) & 0x0F) as usize;
        let a = ((opw >> 4) & 0x0F) as usize;
        let b = (opw & 0x0F) as usize;
        let op = opw >> 12;
        match op {
            0 => {
                t[d] = t[a];
            }
            1 => {
                let ta = t[a];
                let mut ctl = br_i31_add(&mut t[d], &ta, 1);
                ctl |= NOT(br_i31_sub(&mut t[d], cc.p, 0));
                br_i31_sub(&mut t[d], cc.p, ctl);
            }
            2 => {
                let ta = t[a];
                let s = br_i31_sub(&mut t[d], &ta, 1);
                br_i31_add(&mut t[d], cc.p, s);
            }
            3 => {
                let (ta, tb) = (t[a], t[b]);
                br_i31_montymul(&mut t[d], &ta, &tb, cc.p, cc.p0i);
            }
            4 => {
                let mut tp = [0u8; (BR_MAX_EC_SIZE + 7) >> 3];
                let plen = ((cc.p[0] - (cc.p[0] >> 5) + 7) >> 3) as usize;
                br_i31_encode(&mut tp[..plen], plen, cc.p);
                tp[plen - 1] = tp[plen - 1].wrapping_sub(2);
                let (mut ta, mut tb) = (t[a], t[b]);
                br_i31_modpow(&mut t[d], &tp[..plen], plen, cc.p, cc.p0i, &mut ta, &mut tb);
            }
            _ => {
                r &= !br_i31_iszero(&t[d]);
            }
        }
        u += 1;
    }

    /*
     * Copy back result.
     */
    P1.c[0] = t[P1x as usize];
    P1.c[1] = t[(P1x + 1) as usize];
    P1.c[2] = t[(P1x + 2) as usize];
    r
}

fn set_one(x: &mut [u32], p: &[u32]) {
    let plen = ((p[0] + 63) >> 5) as usize;
    for w in x[..plen].iter_mut() {
        *w = 0;
    }
    x[0] = p[0];
    x[1] = 0x00000001;
}

fn point_zero(P: &mut jacobian, cc: &curve_params) {
    *P = jacobian::zeroed();
    P.c[0][0] = cc.p[0];
    P.c[1][0] = cc.p[0];
    P.c[2][0] = cc.p[0];
}

fn point_double(P: &mut jacobian, cc: &curve_params) {
    let pp = P.clone();
    run_code(P, &pp, cc, code_double);
}

fn point_add(P1: &mut jacobian, P2: &jacobian, cc: &curve_params) -> u32 {
    run_code(P1, P2, cc, code_add)
}

fn point_mul(P: &mut jacobian, x: &[u8], cc: &curve_params) {
    /*
     * We do a simple double-and-add ladder with a 2-bit window to make only one
     * add every two doublings. We thus first precompute 2P and 3P.
     */
    let mut P2 = P.clone();
    point_double(&mut P2, cc);
    let mut P3 = P.clone();
    point_add(&mut P3, &P2, cc);

    let mut Q = jacobian::zeroed();
    point_zero(&mut Q, cc);
    let mut qz: u32 = 1;
    for &xb in x.iter() {
        let mut k: i32 = 6;
        while k >= 0 {
            point_double(&mut Q, cc);
            point_double(&mut Q, cc);
            let mut T = P.clone();
            let mut U = Q.clone();
            let bits = ((xb as u32) >> k) & 3;
            let bnz = NEQ(bits, 0);
            CCOPY(EQ(bits, 2), &mut T, &P2);
            CCOPY(EQ(bits, 3), &mut T, &P3);
            point_add(&mut U, &T, cc);
            CCOPY(bnz & qz, &mut Q, &T);
            CCOPY(bnz & !qz, &mut Q, &U);
            qz &= !bnz;
            k -= 2;
        }
    }
    *P = Q;
}

/// Constant-time conditional copy of an entire Jacobian point (`CCOPY`).
fn CCOPY(ctl: u32, dst: &mut jacobian, src: &jacobian) {
    for i in 0..3 {
        ccopy_words(ctl, &mut dst.c[i], &src.c[i], I31_LEN);
    }
}

/*
 * Decode point into Jacobian coordinates. Does not support the point at
 * infinity. Returns 0 (with well-formed field elements) if the point is
 * invalid.
 */
fn point_decode(P: &mut jacobian, src: &[u8], cc: &curve_params) -> u32 {
    point_zero(P, cc);
    let plen = ((cc.p[0] - (cc.p[0] >> 5) + 7) >> 3) as usize;
    if src.len() != 1 + (plen << 1) {
        return 0;
    }
    let mut r = br_i31_decode_mod(&mut P.c[0], &src[1..1 + plen], plen, cc.p);
    r &= br_i31_decode_mod(&mut P.c[1], &src[1 + plen..1 + 2 * plen], plen, cc.p);

    /* Check first byte. */
    r &= EQ(src[0] as u32, 0x04);

    /* Convert coordinates and check that the point is valid. */
    let zlen = ((cc.p[0] + 63) >> 5) as usize;
    let mut Q = jacobian::zeroed();
    Q.c[0][..zlen].copy_from_slice(&cc.R2[..zlen]);
    Q.c[1][..zlen].copy_from_slice(&cc.b[..zlen]);
    set_one(&mut Q.c[2], cc.p);
    r &= !run_code(P, &Q, cc, code_check);
    r
}

/*
 * Encode a point. Assumes the point is correct and not infinity. Encoded size
 * is always 1+2*plen.
 */
fn point_encode(dst: &mut [u8], P: &jacobian, cc: &curve_params) {
    let mut xbl = cc.p[0];
    xbl -= xbl >> 5;
    let plen = ((xbl + 7) >> 3) as usize;
    dst[0] = 0x04;
    let mut Q = P.clone();
    let mut T = jacobian::zeroed();
    set_one(&mut T.c[2], cc.p);
    run_code(&mut Q, &T, cc, code_affine);
    br_i31_encode(&mut dst[1..1 + plen], plen, &Q.c[0]);
    br_i31_encode(&mut dst[1 + plen..1 + 2 * plen], plen, &Q.c[1]);
}

fn id_to_curve_def(curve: i32) -> Option<&'static br_ec_curve_def> {
    match curve {
        BR_EC_secp256r1 => Some(&br_secp256r1),
        BR_EC_secp384r1 => Some(&br_secp384r1),
        BR_EC_secp521r1 => Some(&br_secp521r1),
        _ => None,
    }
}

fn api_generator(curve: i32) -> &'static [u8] {
    id_to_curve_def(curve).unwrap().generator
}

fn api_order(curve: i32) -> &'static [u8] {
    id_to_curve_def(curve).unwrap().order
}

fn api_xoff(curve: i32, len: &mut usize) -> usize {
    *len = api_generator(curve).len() >> 1;
    1
}

fn api_mul(G: &mut [u8], x: &[u8], curve: i32) -> u32 {
    let cc = id_to_curve(curve);
    if G.len() != cc.point_len {
        return 0;
    }
    let mut P = jacobian::zeroed();
    let r = point_decode(&mut P, G, &cc);
    point_mul(&mut P, x, &cc);
    point_encode(G, &P, &cc);
    r
}

fn api_mulgen(R: &mut [u8], x: &[u8], curve: i32) -> usize {
    let g = api_generator(curve);
    let glen = g.len();
    R[..glen].copy_from_slice(g);
    api_mul(&mut R[..glen], x, curve);
    glen
}

fn api_muladd(A: &mut [u8], B: Option<&[u8]>, x: &[u8], y: &[u8], curve: i32) -> u32 {
    let cc = id_to_curve(curve);
    let len = A.len();
    if len != cc.point_len {
        return 0;
    }
    let mut P = jacobian::zeroed();
    let mut Q = jacobian::zeroed();
    let mut r = point_decode(&mut P, A, &cc);
    let b_buf;
    let b_slice: &[u8] = match B {
        Some(b) => b,
        None => {
            b_buf = api_generator(curve);
            b_buf
        }
    };
    r &= point_decode(&mut Q, b_slice, &cc);
    point_mul(&mut P, x, &cc);
    point_mul(&mut Q, y, &cc);

    /*
     * Compute P+Q, then handle the special cases (P==Q, P+Q==0).
     */
    let t = point_add(&mut P, &Q, &cc);
    point_double(&mut Q, &cc);
    let z = br_i31_iszero(&P.c[2]);

    CCOPY(z & !t, &mut P, &Q);
    point_encode(A, &P, &cc);
    r &= !(z & t);

    r
}

/// see bearssl_ec.h
pub static br_ec_prime_i31: br_ec_impl = br_ec_impl {
    supported_curves: 0x03800000,
    generator: api_generator,
    order: api_order,
    xoff: api_xoff,
    mul: api_mul,
    mulgen: api_mulgen,
    muladd: api_muladd,
};
