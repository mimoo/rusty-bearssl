/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! SHA-384 and SHA-512 (`src/hash/sha2big.c`).

use super::*;
use crate::codec::{br_range_dec64be, br_range_enc64be};
use crate::inner::br_enc64be;

#[inline(always)]
fn CH(x: u64, y: u64, z: u64) -> u64 {
    ((y ^ z) & x) ^ z
}
#[inline(always)]
fn MAJ(x: u64, y: u64, z: u64) -> u64 {
    (y & z) | ((y | z) & x)
}
#[inline(always)]
fn ROTR(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}
#[inline(always)]
fn BSG5_0(x: u64) -> u64 {
    ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)
}
#[inline(always)]
fn BSG5_1(x: u64) -> u64 {
    ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)
}
#[inline(always)]
fn SSG5_0(x: u64) -> u64 {
    ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7)
}
#[inline(always)]
fn SSG5_1(x: u64) -> u64 {
    ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6)
}

/// IV for SHA-384 (`IV384` in the C source).
pub static br_sha384_IV: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

/// IV for SHA-512 (`IV512` in the C source).
pub static br_sha512_IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

static K: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

pub fn sha2big_round(buf: &[u8], val: &mut [u64; 8]) {
    let mut w = [0u64; 80];
    br_range_dec64be(&mut w, 16, buf);
    for i in 16..80 {
        w[i] = SSG5_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(SSG5_0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    let mut a = val[0];
    let mut b = val[1];
    let mut c = val[2];
    let mut d = val[3];
    let mut e = val[4];
    let mut f = val[5];
    let mut g = val[6];
    let mut h = val[7];

    macro_rules! STEP {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$F:ident,$G:ident,$H:ident,$j:expr) => {{
            let t1 = $H
                .wrapping_add(BSG5_1($E))
                .wrapping_add(CH($E, $F, $G))
                .wrapping_add(K[$j])
                .wrapping_add(w[$j]);
            let t2 = BSG5_0($A).wrapping_add(MAJ($A, $B, $C));
            $D = $D.wrapping_add(t1);
            $H = t1.wrapping_add(t2);
        }};
    }

    let mut i = 0;
    while i < 80 {
        STEP!(a, b, c, d, e, f, g, h, i + 0);
        STEP!(h, a, b, c, d, e, f, g, i + 1);
        STEP!(g, h, a, b, c, d, e, f, i + 2);
        STEP!(f, g, h, a, b, c, d, e, i + 3);
        STEP!(e, f, g, h, a, b, c, d, i + 4);
        STEP!(d, e, f, g, h, a, b, c, i + 5);
        STEP!(c, d, e, f, g, h, a, b, i + 6);
        STEP!(b, c, d, e, f, g, h, a, i + 7);
        i += 8;
    }
    val[0] = val[0].wrapping_add(a);
    val[1] = val[1].wrapping_add(b);
    val[2] = val[2].wrapping_add(c);
    val[3] = val[3].wrapping_add(d);
    val[4] = val[4].wrapping_add(e);
    val[5] = val[5].wrapping_add(f);
    val[6] = val[6].wrapping_add(g);
    val[7] = val[7].wrapping_add(h);
}

/// SHA-512's compression function, exposed for reuse (e.g. SHAKE shares none,
/// but symmetry with the small variant is kept).
pub use sha2big_round as br_sha512_round;

/// SHA-384/SHA-512 context. SHA-384 and SHA-512 share one context type, as in
/// BearSSL; they differ only by the IV/`vtable` and output truncation.
#[derive(Clone)]
pub struct br_sha384_context {
    pub vtable: &'static br_hash_class,
    pub buf: [u8; 128],
    pub count: u64,
    pub val: [u64; 8],
}

/// SHA-384 and SHA-512 use identical contexts.
pub type br_sha512_context = br_sha384_context;

fn sha2big_update(cc: &mut br_sha384_context, data: &[u8], len: usize) {
    let mut ptr = (cc.count & 127) as usize;
    cc.count += len as u64;
    let mut off = 0;
    let mut len = len;
    while len > 0 {
        let mut clen = 128 - ptr;
        if clen > len {
            clen = len;
        }
        cc.buf[ptr..ptr + clen].copy_from_slice(&data[off..off + clen]);
        ptr += clen;
        off += clen;
        len -= clen;
        if ptr == 128 {
            let buf = cc.buf;
            sha2big_round(&buf, &mut cc.val);
            ptr = 0;
        }
    }
}

fn sha2big_out(cc: &br_sha384_context, dst: &mut [u8], num: usize) {
    let mut buf = [0u8; 128];
    let mut val = cc.val;
    let mut ptr = (cc.count & 127) as usize;
    buf[..ptr].copy_from_slice(&cc.buf[..ptr]);
    buf[ptr] = 0x80;
    ptr += 1;
    if ptr > 112 {
        sha2big_round(&buf, &mut val);
        buf = [0u8; 128];
    }
    br_enc64be(&mut buf[112..], cc.count >> 61);
    br_enc64be(&mut buf[120..], cc.count << 3);
    sha2big_round(&buf, &mut val);
    br_range_enc64be(dst, &val, num);
}

/// see bearssl.h
pub fn br_sha384_init(cc: &mut br_sha384_context) {
    cc.vtable = &br_sha384_vtable;
    cc.val = br_sha384_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_sha384_update(cc: &mut br_sha384_context, data: &[u8], len: usize) {
    sha2big_update(cc, data, len);
}

/// see bearssl.h
pub fn br_sha384_out(cc: &br_sha384_context, dst: &mut [u8]) {
    sha2big_out(cc, dst, 6);
}

/// see bearssl.h
pub fn br_sha384_state(cc: &br_sha384_context, dst: &mut [u8]) -> u64 {
    br_range_enc64be(dst, &cc.val, 8);
    cc.count
}

/// see bearssl.h
pub fn br_sha384_set_state(cc: &mut br_sha384_context, stb: &[u8], count: u64) {
    br_range_dec64be(&mut cc.val, 8, stb);
    cc.count = count;
}

/// see bearssl.h
pub fn br_sha512_init(cc: &mut br_sha512_context) {
    cc.vtable = &br_sha512_vtable;
    cc.val = br_sha512_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_sha512_out(cc: &br_sha512_context, dst: &mut [u8]) {
    sha2big_out(cc, dst, 8);
}

pub use br_sha384_set_state as br_sha512_set_state;
pub use br_sha384_state as br_sha512_state;
pub use br_sha384_update as br_sha512_update;

impl br_sha384_context {
    fn new_sha384() -> Self {
        let mut cc = br_sha384_context {
            vtable: &br_sha384_vtable,
            buf: [0u8; 128],
            count: 0,
            val: [0u64; 8],
        };
        br_sha384_init(&mut cc);
        cc
    }
    fn new_sha512() -> Self {
        let mut cc = br_sha384_context {
            vtable: &br_sha512_vtable,
            buf: [0u8; 128],
            count: 0,
            val: [0u64; 8],
        };
        br_sha512_init(&mut cc);
        cc
    }
}

impl HashState for br_sha384_context {
    fn vtable(&self) -> &'static br_hash_class {
        self.vtable
    }
    fn update(&mut self, data: &[u8]) {
        sha2big_update(self, data, data.len());
    }
    fn out(&self, dst: &mut [u8]) {
        sha2big_out(self, dst, self.vtable.out_size() / 8);
    }
    fn state(&self, dst: &mut [u8]) -> u64 {
        br_range_enc64be(dst, &self.val, 8);
        self.count
    }
    fn set_state(&mut self, stb: &[u8], count: u64) {
        br_range_dec64be(&mut self.val, 8, stb);
        self.count = count;
    }
}

/// see bearssl.h
pub static br_sha384_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_sha384_context>(),
    desc: BR_HASHDESC_ID(br_sha384_ID)
        | BR_HASHDESC_OUT(48)
        | BR_HASHDESC_STATE(64)
        | BR_HASHDESC_LBLEN(7)
        | BR_HASHDESC_MD_PADDING
        | BR_HASHDESC_MD_PADDING_BE
        | BR_HASHDESC_MD_PADDING_128,
    new: || Box::new(br_sha384_context::new_sha384()),
};

/// see bearssl.h
pub static br_sha512_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_sha512_context>(),
    desc: BR_HASHDESC_ID(br_sha512_ID)
        | BR_HASHDESC_OUT(64)
        | BR_HASHDESC_STATE(64)
        | BR_HASHDESC_LBLEN(7)
        | BR_HASHDESC_MD_PADDING
        | BR_HASHDESC_MD_PADDING_BE
        | BR_HASHDESC_MD_PADDING_128,
    new: || Box::new(br_sha384_context::new_sha512()),
};
