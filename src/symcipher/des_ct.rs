/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Constant-time DES / 3DES core (`src/symcipher/des_ct.c`): the bitsliced
//! key schedule (PC-2 + bitslicing), the bitsliced confusion function, and the
//! per-block processing.

use super::des_support::{br_des_do_IP, br_des_do_invIP, br_des_keysched_unit, br_des_rev_skey};
use crate::inner::{br_dec32be, br_enc32be};

/*
 * During key schedule, we need to apply bit extraction PC-2 then permute
 * things into our bitslice representation.
 */

static QL0: [u8; 16] = [
    17, 4, 27, 23, 13, 22, 7, 18, 16, 24, 2, 20, 1, 8, 15, 26,
];

static QR0: [u8; 16] = [
    25, 19, 9, 1, 5, 11, 23, 8, 17, 0, 22, 3, 6, 20, 27, 24,
];

static QL1: [u8; 16] = [
    28, 28, 14, 11, 28, 28, 25, 0, 28, 28, 5, 9, 28, 28, 12, 21,
];

static QR1: [u8; 16] = [
    28, 28, 15, 4, 28, 28, 26, 16, 28, 28, 12, 7, 28, 28, 10, 14,
];

/// 32-bit rotation.
fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

/// Compute key schedule for 8 key bytes (produces 32 subkey words).
fn keysched_unit(skey: &mut [u32], key: &[u8]) {
    br_des_keysched_unit(skey, key);

    /*
     * Apply PC-2 + bitslicing.
     */
    for i in 0..16 {
        let kl = skey[(i << 1) + 0];
        let kr = skey[(i << 1) + 1];
        let mut sk0 = 0u32;
        let mut sk1 = 0u32;
        for j in 0..16 {
            sk0 <<= 1;
            sk1 <<= 1;
            sk0 |= ((kl >> QL0[j]) & 1) << 16;
            sk0 |= (kr >> QR0[j]) & 1;
            sk1 |= ((kl >> QL1[j]) & 1) << 16;
            sk1 |= (kr >> QR1[j]) & 1;
        }

        skey[(i << 1) + 0] = sk0;
        skey[(i << 1) + 1] = sk1;
    }
}

/// see inner.h
pub fn br_des_ct_keysched(skey: &mut [u32], key: &[u8]) -> u32 {
    let key_len = key.len();
    match key_len {
        8 => {
            keysched_unit(skey, key);
            1
        }
        16 => {
            keysched_unit(skey, key);
            keysched_unit(&mut skey[32..], &key[8..]);
            br_des_rev_skey(&mut skey[32..]);
            let (head, tail) = skey.split_at_mut(64);
            tail[..32].copy_from_slice(&head[..32]);
            3
        }
        _ => {
            keysched_unit(skey, key);
            keysched_unit(&mut skey[32..], &key[8..]);
            br_des_rev_skey(&mut skey[32..]);
            keysched_unit(&mut skey[64..], &key[16..]);
            3
        }
    }
}

/// DES confusion function. This function performs expansion E (32 to 48 bits),
/// XOR with subkey, S-boxes, and permutation P.
fn Fconf(r0: u32, sk: &[u32]) -> u32 {
    /*
     * Each 6->4 S-box is virtually turned into four 6->1 boxes; we
     * thus end up with 32 "T-boxes" that are evaluated in parallel
     * with bitslice code.
     *
     * Words x0 to x5 contain the T-box inputs 0 to 5.
     */

    /*
     * Spread input bits over the 6 input words x*.
     */
    let mut x1 = r0 & 0x11111111;
    let mut x2 = (r0 >> 1) & 0x11111111;
    let mut x3 = (r0 >> 2) & 0x11111111;
    let mut x4 = (r0 >> 3) & 0x11111111;
    x1 = (x1 << 4).wrapping_sub(x1);
    x2 = (x2 << 4).wrapping_sub(x2);
    x3 = (x3 << 4).wrapping_sub(x3);
    x4 = (x4 << 4).wrapping_sub(x4);
    let mut x0 = (x4 << 4) | (x4 >> 28);
    let mut x5 = (x1 >> 4) | (x1 << 28);

    /*
     * XOR with the subkey for this round.
     */
    x0 ^= sk[0];
    x1 ^= sk[1];
    x2 ^= sk[2];
    x3 ^= sk[3];
    x4 ^= sk[4];
    x5 ^= sk[5];

    /*
     * The T-boxes are done in parallel, using "fake multiplexers":
     *   y = a ^ (x & b)
     */
    let y0 = 0xEFA72C4Du32 ^ (x0 & 0xEC7AC69C);
    let y1 = 0xAEAAEDFFu32 ^ (x0 & 0x500FB821);
    let y2 = 0x37396665u32 ^ (x0 & 0x40EFA809);
    let y3 = 0x68D7B833u32 ^ (x0 & 0xA5EC0B28);
    let y4 = 0xC9C755BBu32 ^ (x0 & 0x252CF820);
    let y5 = 0x73FC3606u32 ^ (x0 & 0x40205801);
    let y6 = 0xA2A0A918u32 ^ (x0 & 0xE220F929);
    let y7 = 0x8222BD90u32 ^ (x0 & 0x44A3F9E1);
    let y8 = 0xD6B6AC77u32 ^ (x0 & 0x794F104A);
    let y9 = 0x3069300Cu32 ^ (x0 & 0x026F320B);
    let y10 = 0x6CE0D5CCu32 ^ (x0 & 0x7640B01A);
    let y11 = 0x59A9A22Du32 ^ (x0 & 0x238F1572);
    let y12 = 0xAC6D0BD4u32 ^ (x0 & 0x7A63C083);
    let y13 = 0x21C83200u32 ^ (x0 & 0x11CCA000);
    let y14 = 0xA0E62188u32 ^ (x0 & 0x202F69AA);
    /* y15 = 0 ^ (x0 & 0); */
    let y16 = 0xAF7D655Au32 ^ (x0 & 0x51B33BE9);
    let y17 = 0xF0168AA3u32 ^ (x0 & 0x3B0FE8AE);
    let y18 = 0x90AA30C6u32 ^ (x0 & 0x90BF8816);
    let y19 = 0x5AB2750Au32 ^ (x0 & 0x09E34F9B);
    let y20 = 0x5391BE65u32 ^ (x0 & 0x0103BE88);
    let y21 = 0x93372BAFu32 ^ (x0 & 0x49AC8E25);
    let y22 = 0xF288210Cu32 ^ (x0 & 0x922C313D);
    let y23 = 0x920AF5C0u32 ^ (x0 & 0x70EF31B0);
    let y24 = 0x63D312C0u32 ^ (x0 & 0x6A707100);
    let y25 = 0x537B3006u32 ^ (x0 & 0xB97C9011);
    let y26 = 0xA2EFB0A5u32 ^ (x0 & 0xA320C959);
    let y27 = 0xBC8F96A5u32 ^ (x0 & 0x6EA0AB4A);
    let y28 = 0xFAD176A5u32 ^ (x0 & 0x6953DDF8);
    let y29 = 0x665A14A3u32 ^ (x0 & 0xF74F3E2B);
    let y30 = 0xF2EFF0CCu32 ^ (x0 & 0xF0306CAD);
    /* y31 = 0 ^ (x0 & 0); */

    let y0 = y0 ^ (x1 & y1);
    let y1 = y2 ^ (x1 & y3);
    let y2 = y4 ^ (x1 & y5);
    let y3 = y6 ^ (x1 & y7);
    let y4 = y8 ^ (x1 & y9);
    let y5 = y10 ^ (x1 & y11);
    let y6 = y12 ^ (x1 & y13);
    let y7 = y14; /* was: y14 ^ (x1 & y15) */
    let y8 = y16 ^ (x1 & y17);
    let y9 = y18 ^ (x1 & y19);
    let y10 = y20 ^ (x1 & y21);
    let y11 = y22 ^ (x1 & y23);
    let y12 = y24 ^ (x1 & y25);
    let y13 = y26 ^ (x1 & y27);
    let y14 = y28 ^ (x1 & y29);
    let y15 = y30; /* was: y30 ^ (x1 & y31) */

    let y0 = y0 ^ (x2 & y1);
    let y1 = y2 ^ (x2 & y3);
    let y2 = y4 ^ (x2 & y5);
    let y3 = y6 ^ (x2 & y7);
    let y4 = y8 ^ (x2 & y9);
    let y5 = y10 ^ (x2 & y11);
    let y6 = y12 ^ (x2 & y13);
    let y7 = y14 ^ (x2 & y15);

    let y0 = y0 ^ (x3 & y1);
    let y1 = y2 ^ (x3 & y3);
    let y2 = y4 ^ (x3 & y5);
    let y3 = y6 ^ (x3 & y7);

    let y0 = y0 ^ (x4 & y1);
    let y1 = y2 ^ (x4 & y3);

    let y0 = y0 ^ (x5 & y1);

    /*
     * The P permutation.
     */
    let mut z0 = (y0 & 0x00000004) << 3;
    z0 |= (y0 & 0x00004000) << 4;
    z0 |= rotl(y0 & 0x12020120, 5);
    z0 |= (y0 & 0x00100000) << 6;
    z0 |= (y0 & 0x00008000) << 9;
    z0 |= (y0 & 0x04000000) >> 22;
    z0 |= (y0 & 0x00000001) << 11;
    z0 |= rotl(y0 & 0x20000200, 12);
    z0 |= (y0 & 0x00200000) >> 19;
    z0 |= (y0 & 0x00000040) << 14;
    z0 |= (y0 & 0x00010000) << 15;
    z0 |= (y0 & 0x00000002) << 16;
    z0 |= rotl(y0 & 0x40801800, 17);
    z0 |= (y0 & 0x00080000) >> 13;
    z0 |= (y0 & 0x00000010) << 21;
    z0 |= (y0 & 0x01000000) >> 10;
    z0 |= rotl(y0 & 0x88000008, 24);
    z0 |= (y0 & 0x00000480) >> 7;
    z0 |= (y0 & 0x00442000) >> 6;
    z0
}

/// Process one block through 16 successive rounds, omitting the swap in the
/// final round.
fn process_block_unit(pl: &mut u32, pr: &mut u32, sk_exp: &[u32]) {
    let mut l = *pl;
    let mut r = *pr;
    let mut off = 0;
    for _ in 0..16 {
        let t = l ^ Fconf(r, &sk_exp[off..]);
        l = r;
        r = t;
        off += 6;
    }
    *pl = r;
    *pr = l;
}

/// see inner.h
pub fn br_des_ct_process_block(num_rounds: u32, sk_exp: &[u32], block: &mut [u8]) {
    let mut l = br_dec32be(block);
    let mut r = br_dec32be(&block[4..]);
    br_des_do_IP(&mut l, &mut r);
    let mut off = 0;
    for _ in 0..num_rounds {
        process_block_unit(&mut l, &mut r, &sk_exp[off..]);
        off += 96;
    }
    br_des_do_invIP(&mut l, &mut r);
    br_enc32be(block, l);
    br_enc32be(&mut block[4..], r);
}

/// see inner.h
pub fn br_des_ct_skey_expand(sk_exp: &mut [u32], num_rounds: u32, skey: &[u32]) {
    let count = num_rounds << 4;
    let mut si = 0;
    let mut di = 0;
    for _ in 0..count {
        let v = skey[si];
        si += 1;
        let w0 = v & 0x11111111;
        let w1 = (v >> 1) & 0x11111111;
        let w2 = (v >> 2) & 0x11111111;
        let w3 = (v >> 3) & 0x11111111;
        sk_exp[di] = (w0 << 4).wrapping_sub(w0);
        di += 1;
        sk_exp[di] = (w1 << 4).wrapping_sub(w1);
        di += 1;
        sk_exp[di] = (w2 << 4).wrapping_sub(w2);
        di += 1;
        sk_exp[di] = (w3 << 4).wrapping_sub(w3);
        di += 1;
        let v = skey[si];
        si += 1;
        let w0 = v & 0x11111111;
        let w1 = (v >> 1) & 0x11111111;
        sk_exp[di] = (w0 << 4).wrapping_sub(w0);
        di += 1;
        sk_exp[di] = (w1 << 4).wrapping_sub(w1);
        di += 1;
    }
}
