/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Constant-time bitsliced AES core (`src/symcipher/aes_ct.c`): the bitsliced
//! S-box, the orthogonalisation, the bitsliced key schedule, and the subkey
//! expansion. The 32-bit implementation processes two blocks in parallel.

use crate::inner::br_dec32le;

/// see inner.h
pub fn br_aes_ct_bitslice_Sbox(q: &mut [u32; 8]) {
    /*
     * This S-box implementation is a straightforward translation of
     * the circuit described by Boyar and Peralta in "A new
     * combinational logic minimization technique with applications
     * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
     *
     * Note that variables x* (input) and s* (output) are numbered
     * in "reverse" order (x0 is the high bit, x7 is the low bit).
     */

    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    /*
     * Top linear transformation.
     */
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    /*
     * Non-linear section.
     */
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    /*
     * Bottom linear transformation.
     */
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// see inner.h
pub fn br_aes_ct_ortho(q: &mut [u32]) {
    macro_rules! SWAPN {
        ($cl:expr, $ch:expr, $s:expr, $x:expr, $y:expr) => {{
            let a = q[$x];
            let b = q[$y];
            q[$x] = (a & $cl) | ((b & $cl) << $s);
            q[$y] = ((a & $ch) >> $s) | (b & $ch);
        }};
    }
    macro_rules! SWAP2 {
        ($x:expr, $y:expr) => {
            SWAPN!(0x55555555u32, 0xAAAAAAAAu32, 1, $x, $y)
        };
    }
    macro_rules! SWAP4 {
        ($x:expr, $y:expr) => {
            SWAPN!(0x33333333u32, 0xCCCCCCCCu32, 2, $x, $y)
        };
    }
    macro_rules! SWAP8 {
        ($x:expr, $y:expr) => {
            SWAPN!(0x0F0F0F0Fu32, 0xF0F0F0F0u32, 4, $x, $y)
        };
    }

    SWAP2!(0, 1);
    SWAP2!(2, 3);
    SWAP2!(4, 5);
    SWAP2!(6, 7);

    SWAP4!(0, 2);
    SWAP4!(1, 3);
    SWAP4!(4, 6);
    SWAP4!(5, 7);

    SWAP8!(0, 4);
    SWAP8!(1, 5);
    SWAP8!(2, 6);
    SWAP8!(3, 7);
}

static Rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn sub_word(x: u32) -> u32 {
    let mut q = [x; 8];
    br_aes_ct_ortho(&mut q);
    br_aes_ct_bitslice_Sbox(&mut q);
    br_aes_ct_ortho(&mut q);
    q[0]
}

/// see inner.h
pub fn br_aes_ct_keysched(comp_skey: &mut [u32], key: &[u8]) -> u32 {
    let key_len = key.len();
    let num_rounds: u32 = match key_len {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => {
            /* abort(); */
            return 0;
        }
    };
    let nk = (key_len >> 2) as i32;
    let nkf = ((num_rounds + 1) << 2) as i32;
    let mut skey = [0u32; 120];
    let mut tmp = 0u32;
    for i in 0..nk {
        tmp = br_dec32le(&key[(i << 2) as usize..]);
        skey[((i << 1) + 0) as usize] = tmp;
        skey[((i << 1) + 1) as usize] = tmp;
    }
    let mut j = 0i32;
    let mut k = 0usize;
    for i in nk..nkf {
        if j == 0 {
            tmp = (tmp << 24) | (tmp >> 8);
            tmp = sub_word(tmp) ^ Rcon[k] as u32;
        } else if nk > 6 && j == 4 {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[((i - nk) << 1) as usize];
        skey[((i << 1) + 0) as usize] = tmp;
        skey[((i << 1) + 1) as usize] = tmp;
        j += 1;
        if j == nk {
            j = 0;
            k += 1;
        }
    }
    let mut i = 0i32;
    while i < nkf {
        let off = (i << 1) as usize;
        br_aes_ct_ortho(&mut skey[off..off + 8]);
        i += 4;
    }
    let mut j = 0usize;
    for i in 0..nkf as usize {
        comp_skey[i] = (skey[j + 0] & 0x55555555) | (skey[j + 1] & 0xAAAAAAAA);
        j += 2;
    }
    num_rounds
}

/// see inner.h
pub fn br_aes_ct_skey_expand(skey: &mut [u32], num_rounds: u32, comp_skey: &[u32]) {
    let n = ((num_rounds + 1) << 2) as usize;
    let mut v = 0usize;
    for u in 0..n {
        let x0 = comp_skey[u];
        let x = x0 & 0x55555555;
        skey[v + 0] = x | (x << 1);
        let y = x0 & 0xAAAAAAAA;
        skey[v + 1] = y | (y >> 1);
        v += 2;
    }
}
