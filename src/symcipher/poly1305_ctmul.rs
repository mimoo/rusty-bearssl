/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Poly1305 (with ChaCha20) using 32x32->64 multiplications
//! (`src/symcipher/poly1305_ctmul.c`).

use super::chacha20_ct::br_chacha20_run;
use crate::inner::{br_dec32le, br_enc32le, br_enc64le, EQ, GT, MUX};

/// Perform the inner processing of blocks for Poly1305. The accumulator and the
/// `r` key are provided as arrays of 26-bit words (these words are allowed to
/// have an extra bit, i.e. use 27 bits).
///
/// On output, all accumulator words fit on 26 bits, except `acc[1]`, which may
/// be slightly larger (but by a very small amount only).
fn poly1305_inner(acc: &mut [u32; 5], r: &[u32; 5], data: &[u8]) {
    let r0 = r[0];
    let r1 = r[1];
    let r2 = r[2];
    let r3 = r[3];
    let r4 = r[4];

    let u1 = r1.wrapping_mul(5);
    let u2 = r2.wrapping_mul(5);
    let u3 = r3.wrapping_mul(5);
    let u4 = r4.wrapping_mul(5);

    let mut a0 = acc[0];
    let mut a1 = acc[1];
    let mut a2 = acc[2];
    let mut a3 = acc[3];
    let mut a4 = acc[4];

    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        let mut tmp = [0u8; 16];

        /*
         * If there is a partial block, right-pad it with zeros.
         */
        let buf: &[u8] = if len < 16 {
            tmp[..len].copy_from_slice(&data[off..off + len]);
            len = 16;
            &tmp
        } else {
            &data[off..off + 16]
        };

        /*
         * Decode next block and apply the "high bit"; that value is
         * added to the accumulator.
         */
        a0 = a0.wrapping_add(br_dec32le(buf) & 0x03FFFFFF);
        a1 = a1.wrapping_add((br_dec32le(&buf[3..]) >> 2) & 0x03FFFFFF);
        a2 = a2.wrapping_add((br_dec32le(&buf[6..]) >> 4) & 0x03FFFFFF);
        a3 = a3.wrapping_add((br_dec32le(&buf[9..]) >> 6) & 0x03FFFFFF);
        a4 = a4.wrapping_add((br_dec32le(&buf[12..]) >> 8) | 0x01000000);

        /*
         * Compute multiplication.
         */
        macro_rules! M {
            ($x:expr, $y:expr) => {
                ($x as u64) * ($y as u64)
            };
        }

        let w0 = M!(a0, r0) + M!(a1, u4) + M!(a2, u3) + M!(a3, u2) + M!(a4, u1);
        let w1 = M!(a0, r1) + M!(a1, r0) + M!(a2, u4) + M!(a3, u3) + M!(a4, u2);
        let w2 = M!(a0, r2) + M!(a1, r1) + M!(a2, r0) + M!(a3, u4) + M!(a4, u3);
        let w3 = M!(a0, r3) + M!(a1, r2) + M!(a2, r1) + M!(a3, r0) + M!(a4, u4);
        let w4 = M!(a0, r4) + M!(a1, r3) + M!(a2, r2) + M!(a3, r1) + M!(a4, r0);

        /*
         * Perform some (partial) modular reduction with carry
         * propagation.
         */
        let mut c = w0 >> 26;
        a0 = (w0 as u32) & 0x3FFFFFF;
        let w1 = w1 + c;
        c = w1 >> 26;
        a1 = (w1 as u32) & 0x3FFFFFF;
        let w2 = w2 + c;
        c = w2 >> 26;
        a2 = (w2 as u32) & 0x3FFFFFF;
        let w3 = w3 + c;
        c = w3 >> 26;
        a3 = (w3 as u32) & 0x3FFFFFF;
        let w4 = w4 + c;
        c = w4 >> 26;
        a4 = (w4 as u32) & 0x3FFFFFF;
        a0 = a0.wrapping_add((c as u32).wrapping_mul(5));
        a1 = a1.wrapping_add(a0 >> 26);
        a0 &= 0x3FFFFFF;

        off += 16;
        len -= 16;
    }

    acc[0] = a0;
    acc[1] = a1;
    acc[2] = a2;
    acc[3] = a3;
    acc[4] = a4;
}

/// see bearssl_block.h
#[allow(clippy::too_many_arguments)]
pub fn br_poly1305_ctmul_run(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
    aad: &[u8],
    tag: &mut [u8],
    ichacha: br_chacha20_run,
    encrypt: i32,
) {
    let mut pkey = [0u8; 32];
    let mut foot = [0u8; 16];
    let mut r = [0u32; 5];
    let mut acc = [0u32; 5];

    /*
     * Compute the MAC key. The 'r' value is the first 16 bytes of pkey[].
     */
    ichacha(key, iv, 0, &mut pkey);

    /*
     * If encrypting, ChaCha20 must run first, followed by Poly1305.
     * When decrypting, the operations are reversed.
     */
    if encrypt != 0 {
        ichacha(key, iv, 1, data);
    }

    /*
     * Decode the 'r' value into 26-bit words, with the "clamping"
     * operation applied.
     */
    r[0] = br_dec32le(&pkey) & 0x03FFFFFF;
    r[1] = (br_dec32le(&pkey[3..]) >> 2) & 0x03FFFF03;
    r[2] = (br_dec32le(&pkey[6..]) >> 4) & 0x03FFC0FF;
    r[3] = (br_dec32le(&pkey[9..]) >> 6) & 0x03F03FFF;
    r[4] = (br_dec32le(&pkey[12..]) >> 8) & 0x000FFFFF;

    /*
     * Process the additional authenticated data, ciphertext, and footer
     * in due order.
     */
    br_enc64le(&mut foot, aad.len() as u64);
    br_enc64le(&mut foot[8..], data.len() as u64);
    poly1305_inner(&mut acc, &r, aad);
    poly1305_inner(&mut acc, &r, data);
    poly1305_inner(&mut acc, &r, &foot);

    /*
     * Finalise modular reduction.
     */
    let mut cc = 0u32;
    for i in 1..=6 {
        let j = if i >= 5 { i - 5 } else { i };
        acc[j] = acc[j].wrapping_add(cc);
        cc = acc[j] >> 26;
        acc[j] &= 0x03FFFFFF;
    }

    /*
     * We may still have a value in the 2^130-5..2^130-1 range, in which
     * case we must reduce it again. Select, in constant time, between
     * 'acc' and 'acc-p'.
     */
    let mut ctl = GT(acc[0], 0x03FFFFFA);
    for i in 1..5 {
        ctl &= EQ(acc[i], 0x03FFFFFF);
    }
    cc = 5;
    for i in 0..5 {
        let t = acc[i].wrapping_add(cc);
        cc = t >> 26;
        let t = t & 0x03FFFFFF;
        acc[i] = MUX(ctl, t, acc[i]);
    }

    /*
     * Convert back the accumulator to 32-bit words, and add the 's' value
     * (second half of pkey[]). That addition is done modulo 2^128.
     */
    let mut w: u64 =
        acc[0] as u64 + ((acc[1] as u64) << 26) + br_dec32le(&pkey[16..]) as u64;
    br_enc32le(&mut tag[0..], w as u32);
    w = (w >> 32) + ((acc[2] as u64) << 20) + br_dec32le(&pkey[20..]) as u64;
    br_enc32le(&mut tag[4..], w as u32);
    w = (w >> 32) + ((acc[3] as u64) << 14) + br_dec32le(&pkey[24..]) as u64;
    br_enc32le(&mut tag[8..], w as u32);
    let hi = ((w >> 32) as u32)
        .wrapping_add(acc[4] << 8)
        .wrapping_add(br_dec32le(&pkey[28..]));
    br_enc32le(&mut tag[12..], hi);

    /*
     * If decrypting, then ChaCha20 runs _after_ Poly1305.
     */
    if encrypt == 0 {
        ichacha(key, iv, 1, data);
    }
}
