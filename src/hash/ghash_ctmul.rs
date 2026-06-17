/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! GHASH using mixed 32-bit multiplications (`src/hash/ghash_ctmul.c`).
//!
//! Constant-time (when multiplications are). This ports the default
//! (`!BR_SLOW_MUL`) variant of `bmul`, which uses 16 integer multiplications.

use crate::inner::{br_dec32be, br_enc32be, MUL};

/// Simple carryless multiplication in GF(2)[X], using 16 integer
/// multiplications. Returns (hi, lo).
#[inline(always)]
fn bmul(x: u32, y: u32) -> (u32, u32) {
    let x0 = x & 0x11111111;
    let x1 = x & 0x22222222;
    let x2 = x & 0x44444444;
    let x3 = x & 0x88888888;
    let y0 = y & 0x11111111;
    let y1 = y & 0x22222222;
    let y2 = y & 0x44444444;
    let y3 = y & 0x88888888;
    let mut z0 = MUL(x0, y0) ^ MUL(x1, y3) ^ MUL(x2, y2) ^ MUL(x3, y1);
    let mut z1 = MUL(x0, y1) ^ MUL(x1, y0) ^ MUL(x2, y3) ^ MUL(x3, y2);
    let mut z2 = MUL(x0, y2) ^ MUL(x1, y1) ^ MUL(x2, y0) ^ MUL(x3, y3);
    let mut z3 = MUL(x0, y3) ^ MUL(x1, y2) ^ MUL(x2, y1) ^ MUL(x3, y0);
    z0 &= 0x1111111111111111;
    z1 &= 0x2222222222222222;
    z2 &= 0x4444444444444444;
    z3 &= 0x8888888888888888;
    let z = z0 | z1 | z2 | z3;
    (((z >> 32) as u32), (z as u32))
}

/// see bearssl_hash.h
pub fn br_ghash_ctmul(y: &mut [u8], h: &[u8], data: &[u8]) {
    let mut yw = [0u32; 4];
    let mut hw = [0u32; 4];
    let mut buf = data;
    let mut len = data.len();

    yw[3] = br_dec32be(y);
    yw[2] = br_dec32be(&y[4..]);
    yw[1] = br_dec32be(&y[8..]);
    yw[0] = br_dec32be(&y[12..]);
    hw[3] = br_dec32be(h);
    hw[2] = br_dec32be(&h[4..]);
    hw[1] = br_dec32be(&h[8..]);
    hw[0] = br_dec32be(&h[12..]);

    while len > 0 {
        let mut tmp = [0u8; 16];
        let src: &[u8] = if len >= 16 {
            let s = &buf[..16];
            buf = &buf[16..];
            len -= 16;
            s
        } else {
            tmp[..len].copy_from_slice(&buf[..len]);
            len = 0;
            &tmp
        };

        yw[3] ^= br_dec32be(src);
        yw[2] ^= br_dec32be(&src[4..]);
        yw[1] ^= br_dec32be(&src[8..]);
        yw[0] ^= br_dec32be(&src[12..]);

        let mut a = [0u32; 9];
        let mut b = [0u32; 9];
        a[0] = yw[0];
        b[0] = hw[0];
        a[1] = yw[1];
        b[1] = hw[1];
        a[2] = a[0] ^ a[1];
        b[2] = b[0] ^ b[1];

        a[3] = yw[2];
        b[3] = hw[2];
        a[4] = yw[3];
        b[4] = hw[3];
        a[5] = a[3] ^ a[4];
        b[5] = b[3] ^ b[4];

        a[6] = a[0] ^ a[3];
        b[6] = b[0] ^ b[3];
        a[7] = a[1] ^ a[4];
        b[7] = b[1] ^ b[4];
        a[8] = a[6] ^ a[7];
        b[8] = b[6] ^ b[7];

        for i in 0..9 {
            let (hi, lo) = bmul(b[i], a[i]);
            b[i] = hi;
            a[i] = lo;
        }

        let c0 = a[0];
        let c1 = b[0] ^ a[2] ^ a[0] ^ a[1];
        let mut c2 = a[1] ^ b[2] ^ b[0] ^ b[1];
        let mut c3 = b[1];
        let mut d0 = a[3];
        let mut d1 = b[3] ^ a[5] ^ a[3] ^ a[4];
        let d2 = a[4] ^ b[5] ^ b[3] ^ b[4];
        let d3 = b[4];
        let mut e0 = a[6];
        let mut e1 = b[6] ^ a[8] ^ a[6] ^ a[7];
        let mut e2 = a[7] ^ b[8] ^ b[6] ^ b[7];
        let mut e3 = b[7];

        e0 ^= c0 ^ d0;
        e1 ^= c1 ^ d1;
        e2 ^= c2 ^ d2;
        e3 ^= c3 ^ d3;
        c2 ^= e0;
        c3 ^= e1;
        d0 ^= e2;
        d1 ^= e3;

        let mut zw = [0u32; 8];
        zw[0] = c0 << 1;
        zw[1] = (c1 << 1) | (c0 >> 31);
        zw[2] = (c2 << 1) | (c1 >> 31);
        zw[3] = (c3 << 1) | (c2 >> 31);
        zw[4] = (d0 << 1) | (c3 >> 31);
        zw[5] = (d1 << 1) | (d0 >> 31);
        zw[6] = (d2 << 1) | (d1 >> 31);
        zw[7] = (d3 << 1) | (d2 >> 31);

        for i in 0..4 {
            let lw = zw[i];
            zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
            zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
        }
        yw.copy_from_slice(&zw[4..8]);
    }

    br_enc32be(y, yw[3]);
    br_enc32be(&mut y[4..], yw[2]);
    br_enc32be(&mut y[8..], yw[1]);
    br_enc32be(&mut y[12..], yw[0]);
}
