/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Constant-time bitsliced AES decryption (`src/symcipher/aes_ct_dec.c`).

use super::aes_ct::br_aes_ct_bitslice_Sbox;

/// see inner.h
pub fn br_aes_ct_bitslice_invSbox(q: &mut [u32; 8]) {
    /*
     * AES S-box is:
     *   S(x) = A(I(x)) ^ 0x63
     * where I() is inversion in GF(256), and A() is a linear
     * transform (0 is formally defined to be its own inverse).
     * Since inversion is an involution, the inverse S-box can be
     * computed from the S-box as:
     *   iS(x) = B(S(B(x ^ 0x63)) ^ 0x63)
     * where B() is the inverse of A().
     */
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;

    br_aes_ct_bitslice_Sbox(q);

    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

fn add_round_key(q: &mut [u32; 8], sk: &[u32]) {
    for i in 0..8 {
        q[i] ^= sk[i];
    }
}

fn inv_shift_rows(q: &mut [u32; 8]) {
    for i in 0..8 {
        let x = q[i];
        q[i] = (x & 0x000000FF)
            | ((x & 0x00003F00) << 2)
            | ((x & 0x0000C000) >> 6)
            | ((x & 0x000F0000) << 4)
            | ((x & 0x00F00000) >> 4)
            | ((x & 0x03000000) << 6)
            | ((x & 0xFC000000) >> 2);
    }
}

fn rotr16(x: u32) -> u32 {
    (x << 16) | (x >> 16)
}

fn inv_mix_columns(q: &mut [u32; 8]) {
    let q0 = q[0];
    let q1 = q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = q[5];
    let q6 = q[6];
    let q7 = q[7];
    let r0 = (q0 >> 8) | (q0 << 24);
    let r1 = (q1 >> 8) | (q1 << 24);
    let r2 = (q2 >> 8) | (q2 << 24);
    let r3 = (q3 >> 8) | (q3 << 24);
    let r4 = (q4 >> 8) | (q4 << 24);
    let r5 = (q5 >> 8) | (q5 << 24);
    let r6 = (q6 >> 8) | (q6 << 24);
    let r7 = (q7 >> 8) | (q7 << 24);

    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotr16(q0 ^ q5 ^ q6 ^ r0 ^ r5);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotr16(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotr16(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7);
    q[3] = q0 ^ q1 ^ q2 ^ q5 ^ q6 ^ r0 ^ r2 ^ r3 ^ r5
        ^ rotr16(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7);
    q[4] = q1 ^ q2 ^ q3 ^ q5 ^ r1 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7
        ^ rotr16(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6);
    q[5] = q2 ^ q3 ^ q4 ^ q6 ^ r2 ^ r4 ^ r5 ^ r6 ^ r7
        ^ rotr16(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7);
    q[6] = q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7 ^ rotr16(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotr16(q4 ^ q5 ^ q7 ^ r4 ^ r7);
}

/// see inner.h
pub fn br_aes_ct_bitslice_decrypt(num_rounds: u32, skey: &[u32], q: &mut [u32; 8]) {
    add_round_key(q, &skey[(num_rounds << 3) as usize..]);
    let mut u = num_rounds - 1;
    while u > 0 {
        inv_shift_rows(q);
        br_aes_ct_bitslice_invSbox(q);
        add_round_key(q, &skey[(u << 3) as usize..]);
        inv_mix_columns(q);
        u -= 1;
    }
    inv_shift_rows(q);
    br_aes_ct_bitslice_invSbox(q);
    add_round_key(q, skey);
}
