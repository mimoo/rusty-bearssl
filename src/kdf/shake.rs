/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! SHAKE128 / SHAKE256 (`src/kdf/shake.c`), the Keccak-based extendable-output
//! functions from FIPS 202.
//!
//! The Keccak-f[1600] permutation (`process_block`) is ported verbatim from the
//! C source, including its lane-complementing trick (six lanes are kept
//! complemented in the state, which is why `br_shake_init` sets them to all-ones
//! and `br_shake_produce` re-complements them on output).

use crate::inner::{br_dec64le, br_enc64le};

/// Round constants for Keccak-f[1600].
static RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// SHAKE context (`br_shake_context`).
pub struct br_shake_context {
    pub dbuf: [u8; 200],
    pub dptr: usize,
    pub rate: usize,
    pub A: [u64; 25],
}

impl Default for br_shake_context {
    fn default() -> Self {
        br_shake_context {
            dbuf: [0u8; 200],
            dptr: 0,
            rate: 0,
            A: [0u64; 25],
        }
    }
}

/// XOR a block of data into the provided state. This supports only blocks whose
/// length is a multiple of 64 bits.
fn xor_block(A: &mut [u64; 25], data: &[u8], rate: usize) {
    let mut u = 0;
    while u < rate {
        A[u >> 3] ^= br_dec64le(&data[u..]);
        u += 8;
    }
}

/// Process a block (the Keccak-f[1600] permutation). Ported verbatim from the C
/// source; the loop is partially unrolled (each iteration computes two rounds).
fn process_block(A: &mut [u64; 25]) {
    let mut j = 0;
    while j < 24 {
        let (mut tt0, mut tt1, mut tt2, mut tt3);
        let (mut t0, mut t1, mut t2, mut t3, mut t4);
        let (mut c0, mut c1, mut c2, mut c3, mut c4, mut bnn, mut kt);

        tt0 = A[1] ^ A[6];
        tt1 = A[11] ^ A[16];
        tt0 ^= A[21] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[4] ^ A[9];
        tt3 = A[14] ^ A[19];
        tt0 ^= A[24];
        tt2 ^= tt3;
        t0 = tt0 ^ tt2;

        tt0 = A[2] ^ A[7];
        tt1 = A[12] ^ A[17];
        tt0 ^= A[22] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[0] ^ A[5];
        tt3 = A[10] ^ A[15];
        tt0 ^= A[20];
        tt2 ^= tt3;
        t1 = tt0 ^ tt2;

        tt0 = A[3] ^ A[8];
        tt1 = A[13] ^ A[18];
        tt0 ^= A[23] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[1] ^ A[6];
        tt3 = A[11] ^ A[16];
        tt0 ^= A[21];
        tt2 ^= tt3;
        t2 = tt0 ^ tt2;

        tt0 = A[4] ^ A[9];
        tt1 = A[14] ^ A[19];
        tt0 ^= A[24] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[2] ^ A[7];
        tt3 = A[12] ^ A[17];
        tt0 ^= A[22];
        tt2 ^= tt3;
        t3 = tt0 ^ tt2;

        tt0 = A[0] ^ A[5];
        tt1 = A[10] ^ A[15];
        tt0 ^= A[20] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[3] ^ A[8];
        tt3 = A[13] ^ A[18];
        tt0 ^= A[23];
        tt2 ^= tt3;
        t4 = tt0 ^ tt2;

        A[0] ^= t0;
        A[5] ^= t0;
        A[10] ^= t0;
        A[15] ^= t0;
        A[20] ^= t0;
        A[1] ^= t1;
        A[6] ^= t1;
        A[11] ^= t1;
        A[16] ^= t1;
        A[21] ^= t1;
        A[2] ^= t2;
        A[7] ^= t2;
        A[12] ^= t2;
        A[17] ^= t2;
        A[22] ^= t2;
        A[3] ^= t3;
        A[8] ^= t3;
        A[13] ^= t3;
        A[18] ^= t3;
        A[23] ^= t3;
        A[4] ^= t4;
        A[9] ^= t4;
        A[14] ^= t4;
        A[19] ^= t4;
        A[24] ^= t4;
        A[5] = (A[5] << 36) | (A[5] >> (64 - 36));
        A[10] = (A[10] << 3) | (A[10] >> (64 - 3));
        A[15] = (A[15] << 41) | (A[15] >> (64 - 41));
        A[20] = (A[20] << 18) | (A[20] >> (64 - 18));
        A[1] = (A[1] << 1) | (A[1] >> (64 - 1));
        A[6] = (A[6] << 44) | (A[6] >> (64 - 44));
        A[11] = (A[11] << 10) | (A[11] >> (64 - 10));
        A[16] = (A[16] << 45) | (A[16] >> (64 - 45));
        A[21] = (A[21] << 2) | (A[21] >> (64 - 2));
        A[2] = (A[2] << 62) | (A[2] >> (64 - 62));
        A[7] = (A[7] << 6) | (A[7] >> (64 - 6));
        A[12] = (A[12] << 43) | (A[12] >> (64 - 43));
        A[17] = (A[17] << 15) | (A[17] >> (64 - 15));
        A[22] = (A[22] << 61) | (A[22] >> (64 - 61));
        A[3] = (A[3] << 28) | (A[3] >> (64 - 28));
        A[8] = (A[8] << 55) | (A[8] >> (64 - 55));
        A[13] = (A[13] << 25) | (A[13] >> (64 - 25));
        A[18] = (A[18] << 21) | (A[18] >> (64 - 21));
        A[23] = (A[23] << 56) | (A[23] >> (64 - 56));
        A[4] = (A[4] << 27) | (A[4] >> (64 - 27));
        A[9] = (A[9] << 20) | (A[9] >> (64 - 20));
        A[14] = (A[14] << 39) | (A[14] >> (64 - 39));
        A[19] = (A[19] << 8) | (A[19] >> (64 - 8));
        A[24] = (A[24] << 14) | (A[24] >> (64 - 14));
        bnn = !A[12];
        kt = A[6] | A[12];
        c0 = A[0] ^ kt;
        kt = bnn | A[18];
        c1 = A[6] ^ kt;
        kt = A[18] & A[24];
        c2 = A[12] ^ kt;
        kt = A[24] | A[0];
        c3 = A[18] ^ kt;
        kt = A[0] & A[6];
        c4 = A[24] ^ kt;
        A[0] = c0;
        A[6] = c1;
        A[12] = c2;
        A[18] = c3;
        A[24] = c4;
        bnn = !A[22];
        kt = A[9] | A[10];
        c0 = A[3] ^ kt;
        kt = A[10] & A[16];
        c1 = A[9] ^ kt;
        kt = A[16] | bnn;
        c2 = A[10] ^ kt;
        kt = A[22] | A[3];
        c3 = A[16] ^ kt;
        kt = A[3] & A[9];
        c4 = A[22] ^ kt;
        A[3] = c0;
        A[9] = c1;
        A[10] = c2;
        A[16] = c3;
        A[22] = c4;
        bnn = !A[19];
        kt = A[7] | A[13];
        c0 = A[1] ^ kt;
        kt = A[13] & A[19];
        c1 = A[7] ^ kt;
        kt = bnn & A[20];
        c2 = A[13] ^ kt;
        kt = A[20] | A[1];
        c3 = bnn ^ kt;
        kt = A[1] & A[7];
        c4 = A[20] ^ kt;
        A[1] = c0;
        A[7] = c1;
        A[13] = c2;
        A[19] = c3;
        A[20] = c4;
        bnn = !A[17];
        kt = A[5] & A[11];
        c0 = A[4] ^ kt;
        kt = A[11] | A[17];
        c1 = A[5] ^ kt;
        kt = bnn | A[23];
        c2 = A[11] ^ kt;
        kt = A[23] & A[4];
        c3 = bnn ^ kt;
        kt = A[4] | A[5];
        c4 = A[23] ^ kt;
        A[4] = c0;
        A[5] = c1;
        A[11] = c2;
        A[17] = c3;
        A[23] = c4;
        bnn = !A[8];
        kt = bnn & A[14];
        c0 = A[2] ^ kt;
        kt = A[14] | A[15];
        c1 = bnn ^ kt;
        kt = A[15] & A[21];
        c2 = A[14] ^ kt;
        kt = A[21] | A[2];
        c3 = A[15] ^ kt;
        kt = A[2] & A[8];
        c4 = A[21] ^ kt;
        A[2] = c0;
        A[8] = c1;
        A[14] = c2;
        A[15] = c3;
        A[21] = c4;
        A[0] ^= RC[j];

        tt0 = A[6] ^ A[9];
        tt1 = A[7] ^ A[5];
        tt0 ^= A[8] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[24] ^ A[22];
        tt3 = A[20] ^ A[23];
        tt0 ^= A[21];
        tt2 ^= tt3;
        t0 = tt0 ^ tt2;

        tt0 = A[12] ^ A[10];
        tt1 = A[13] ^ A[11];
        tt0 ^= A[14] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[0] ^ A[3];
        tt3 = A[1] ^ A[4];
        tt0 ^= A[2];
        tt2 ^= tt3;
        t1 = tt0 ^ tt2;

        tt0 = A[18] ^ A[16];
        tt1 = A[19] ^ A[17];
        tt0 ^= A[15] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[6] ^ A[9];
        tt3 = A[7] ^ A[5];
        tt0 ^= A[8];
        tt2 ^= tt3;
        t2 = tt0 ^ tt2;

        tt0 = A[24] ^ A[22];
        tt1 = A[20] ^ A[23];
        tt0 ^= A[21] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[12] ^ A[10];
        tt3 = A[13] ^ A[11];
        tt0 ^= A[14];
        tt2 ^= tt3;
        t3 = tt0 ^ tt2;

        tt0 = A[0] ^ A[3];
        tt1 = A[1] ^ A[4];
        tt0 ^= A[2] ^ tt1;
        tt0 = (tt0 << 1) | (tt0 >> 63);
        tt2 = A[18] ^ A[16];
        tt3 = A[19] ^ A[17];
        tt0 ^= A[15];
        tt2 ^= tt3;
        t4 = tt0 ^ tt2;

        A[0] ^= t0;
        A[3] ^= t0;
        A[1] ^= t0;
        A[4] ^= t0;
        A[2] ^= t0;
        A[6] ^= t1;
        A[9] ^= t1;
        A[7] ^= t1;
        A[5] ^= t1;
        A[8] ^= t1;
        A[12] ^= t2;
        A[10] ^= t2;
        A[13] ^= t2;
        A[11] ^= t2;
        A[14] ^= t2;
        A[18] ^= t3;
        A[16] ^= t3;
        A[19] ^= t3;
        A[17] ^= t3;
        A[15] ^= t3;
        A[24] ^= t4;
        A[22] ^= t4;
        A[20] ^= t4;
        A[23] ^= t4;
        A[21] ^= t4;
        A[3] = (A[3] << 36) | (A[3] >> (64 - 36));
        A[1] = (A[1] << 3) | (A[1] >> (64 - 3));
        A[4] = (A[4] << 41) | (A[4] >> (64 - 41));
        A[2] = (A[2] << 18) | (A[2] >> (64 - 18));
        A[6] = (A[6] << 1) | (A[6] >> (64 - 1));
        A[9] = (A[9] << 44) | (A[9] >> (64 - 44));
        A[7] = (A[7] << 10) | (A[7] >> (64 - 10));
        A[5] = (A[5] << 45) | (A[5] >> (64 - 45));
        A[8] = (A[8] << 2) | (A[8] >> (64 - 2));
        A[12] = (A[12] << 62) | (A[12] >> (64 - 62));
        A[10] = (A[10] << 6) | (A[10] >> (64 - 6));
        A[13] = (A[13] << 43) | (A[13] >> (64 - 43));
        A[11] = (A[11] << 15) | (A[11] >> (64 - 15));
        A[14] = (A[14] << 61) | (A[14] >> (64 - 61));
        A[18] = (A[18] << 28) | (A[18] >> (64 - 28));
        A[16] = (A[16] << 55) | (A[16] >> (64 - 55));
        A[19] = (A[19] << 25) | (A[19] >> (64 - 25));
        A[17] = (A[17] << 21) | (A[17] >> (64 - 21));
        A[15] = (A[15] << 56) | (A[15] >> (64 - 56));
        A[24] = (A[24] << 27) | (A[24] >> (64 - 27));
        A[22] = (A[22] << 20) | (A[22] >> (64 - 20));
        A[20] = (A[20] << 39) | (A[20] >> (64 - 39));
        A[23] = (A[23] << 8) | (A[23] >> (64 - 8));
        A[21] = (A[21] << 14) | (A[21] >> (64 - 14));
        bnn = !A[13];
        kt = A[9] | A[13];
        c0 = A[0] ^ kt;
        kt = bnn | A[17];
        c1 = A[9] ^ kt;
        kt = A[17] & A[21];
        c2 = A[13] ^ kt;
        kt = A[21] | A[0];
        c3 = A[17] ^ kt;
        kt = A[0] & A[9];
        c4 = A[21] ^ kt;
        A[0] = c0;
        A[9] = c1;
        A[13] = c2;
        A[17] = c3;
        A[21] = c4;
        bnn = !A[14];
        kt = A[22] | A[1];
        c0 = A[18] ^ kt;
        kt = A[1] & A[5];
        c1 = A[22] ^ kt;
        kt = A[5] | bnn;
        c2 = A[1] ^ kt;
        kt = A[14] | A[18];
        c3 = A[5] ^ kt;
        kt = A[18] & A[22];
        c4 = A[14] ^ kt;
        A[18] = c0;
        A[22] = c1;
        A[1] = c2;
        A[5] = c3;
        A[14] = c4;
        bnn = !A[23];
        kt = A[10] | A[19];
        c0 = A[6] ^ kt;
        kt = A[19] & A[23];
        c1 = A[10] ^ kt;
        kt = bnn & A[2];
        c2 = A[19] ^ kt;
        kt = A[2] | A[6];
        c3 = bnn ^ kt;
        kt = A[6] & A[10];
        c4 = A[2] ^ kt;
        A[6] = c0;
        A[10] = c1;
        A[19] = c2;
        A[23] = c3;
        A[2] = c4;
        bnn = !A[11];
        kt = A[3] & A[7];
        c0 = A[24] ^ kt;
        kt = A[7] | A[11];
        c1 = A[3] ^ kt;
        kt = bnn | A[15];
        c2 = A[7] ^ kt;
        kt = A[15] & A[24];
        c3 = bnn ^ kt;
        kt = A[24] | A[3];
        c4 = A[15] ^ kt;
        A[24] = c0;
        A[3] = c1;
        A[7] = c2;
        A[11] = c3;
        A[15] = c4;
        bnn = !A[16];
        kt = bnn & A[20];
        c0 = A[12] ^ kt;
        kt = A[20] | A[4];
        c1 = bnn ^ kt;
        kt = A[4] & A[8];
        c2 = A[20] ^ kt;
        kt = A[8] | A[12];
        c3 = A[4] ^ kt;
        kt = A[12] & A[16];
        c4 = A[8] ^ kt;
        A[12] = c0;
        A[16] = c1;
        A[20] = c2;
        A[4] = c3;
        A[8] = c4;
        A[0] ^= RC[j + 1];

        let mut t = A[5];
        A[5] = A[18];
        A[18] = A[11];
        A[11] = A[10];
        A[10] = A[6];
        A[6] = A[22];
        A[22] = A[20];
        A[20] = A[12];
        A[12] = A[19];
        A[19] = A[15];
        A[15] = A[24];
        A[24] = A[8];
        A[8] = t;
        t = A[1];
        A[1] = A[9];
        A[9] = A[14];
        A[14] = A[2];
        A[2] = A[13];
        A[13] = A[23];
        A[23] = A[4];
        A[4] = A[21];
        A[21] = A[16];
        A[16] = A[3];
        A[3] = A[17];
        A[17] = A[7];
        A[7] = t;

        j += 2;
    }
}

/// see bearssl_kdf.h
pub fn br_shake_init(sc: &mut br_shake_context, security_level: i32) {
    sc.rate = 200 - (security_level >> 2) as usize;
    sc.dptr = 0;
    sc.A = [0u64; 25];
    sc.A[1] = !0u64;
    sc.A[2] = !0u64;
    sc.A[8] = !0u64;
    sc.A[12] = !0u64;
    sc.A[17] = !0u64;
    sc.A[20] = !0u64;
}

/// see bearssl_kdf.h
pub fn br_shake_inject(sc: &mut br_shake_context, data: &[u8]) {
    let rate = sc.rate;
    let mut dptr = sc.dptr;
    let mut off = 0usize;
    let mut len = data.len();
    while len > 0 {
        let mut clen = rate - dptr;
        if clen > len {
            clen = len;
        }
        sc.dbuf[dptr..dptr + clen].copy_from_slice(&data[off..off + clen]);
        dptr += clen;
        off += clen;
        len -= clen;
        if dptr == rate {
            let dbuf = sc.dbuf;
            xor_block(&mut sc.A, &dbuf, rate);
            process_block(&mut sc.A);
            dptr = 0;
        }
    }
    sc.dptr = dptr;
}

/// see bearssl_kdf.h
pub fn br_shake_flip(sc: &mut br_shake_context) {
    // We apply padding and pre-XOR the value into the state. We set dptr to the
    // end of the buffer, so that the first call to br_shake_produce() will
    // process the block.
    if (sc.dptr + 1) == sc.rate {
        sc.dbuf[sc.dptr] = 0x9F;
        sc.dptr += 1;
    } else {
        sc.dbuf[sc.dptr] = 0x1F;
        sc.dptr += 1;
        for b in sc.dbuf[sc.dptr..sc.rate - 1].iter_mut() {
            *b = 0x00;
        }
        sc.dbuf[sc.rate - 1] = 0x80;
        sc.dptr = sc.rate;
    }
    let dbuf = sc.dbuf;
    let rate = sc.rate;
    xor_block(&mut sc.A, &dbuf, rate);
}

/// see bearssl_kdf.h
pub fn br_shake_produce(sc: &mut br_shake_context, out: &mut [u8], len: usize) {
    let mut dptr = sc.dptr;
    let rate = sc.rate;
    let mut off = 0usize;
    let mut len = len;
    while len > 0 {
        if dptr == rate {
            process_block(&mut sc.A);
            let a = &sc.A;
            br_enc64le(&mut sc.dbuf[0..], a[0]);
            br_enc64le(&mut sc.dbuf[8..], !a[1]);
            br_enc64le(&mut sc.dbuf[16..], !a[2]);
            br_enc64le(&mut sc.dbuf[24..], a[3]);
            br_enc64le(&mut sc.dbuf[32..], a[4]);
            br_enc64le(&mut sc.dbuf[40..], a[5]);
            br_enc64le(&mut sc.dbuf[48..], a[6]);
            br_enc64le(&mut sc.dbuf[56..], a[7]);
            br_enc64le(&mut sc.dbuf[64..], !a[8]);
            br_enc64le(&mut sc.dbuf[72..], a[9]);
            br_enc64le(&mut sc.dbuf[80..], a[10]);
            br_enc64le(&mut sc.dbuf[88..], a[11]);
            br_enc64le(&mut sc.dbuf[96..], !a[12]);
            br_enc64le(&mut sc.dbuf[104..], a[13]);
            br_enc64le(&mut sc.dbuf[112..], a[14]);
            br_enc64le(&mut sc.dbuf[120..], a[15]);
            br_enc64le(&mut sc.dbuf[128..], a[16]);
            br_enc64le(&mut sc.dbuf[136..], !a[17]);
            br_enc64le(&mut sc.dbuf[144..], a[18]);
            br_enc64le(&mut sc.dbuf[152..], a[19]);
            br_enc64le(&mut sc.dbuf[160..], !a[20]);
            br_enc64le(&mut sc.dbuf[168..], a[21]);
            br_enc64le(&mut sc.dbuf[176..], a[22]);
            br_enc64le(&mut sc.dbuf[184..], a[23]);
            br_enc64le(&mut sc.dbuf[192..], a[24]);
            dptr = 0;
        }
        let mut clen = rate - dptr;
        if clen > len {
            clen = len;
        }
        out[off..off + clen].copy_from_slice(&sc.dbuf[dptr..dptr + clen]);
        dptr += clen;
        off += clen;
        len -= clen;
    }
    sc.dptr = dptr;
}

impl br_shake_context {
    /// Create and initialize a SHAKE context for the given security level
    /// (128 or 256).
    pub fn new(security_level: i32) -> Self {
        let mut sc = br_shake_context::default();
        br_shake_init(&mut sc, security_level);
        sc
    }
}
