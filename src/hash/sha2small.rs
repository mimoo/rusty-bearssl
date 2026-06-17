/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! SHA-224 and SHA-256 (`src/hash/sha2small.c`).

use super::*;
use crate::codec::{br_range_dec32be, br_range_enc32be};
use crate::inner::br_enc64be;

#[inline(always)]
fn CH(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}
#[inline(always)]
fn MAJ(x: u32, y: u32, z: u32) -> u32 {
    (y & z) | ((y | z) & x)
}
#[inline(always)]
fn ROTR(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}
#[inline(always)]
fn BSG2_0(x: u32) -> u32 {
    ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
}
#[inline(always)]
fn BSG2_1(x: u32) -> u32 {
    ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
}
#[inline(always)]
fn SSG2_0(x: u32) -> u32 {
    ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3)
}
#[inline(always)]
fn SSG2_1(x: u32) -> u32 {
    ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10)
}

/// see inner.h
pub static br_sha224_IV: [u32; 8] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
];

/// see inner.h
pub static br_sha256_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

static K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// see inner.h
pub fn br_sha2small_round(buf: &[u8], val: &mut [u32; 8]) {
    let mut w = [0u32; 64];
    br_range_dec32be(&mut w, 16, buf);
    for i in 16..64 {
        w[i] = SSG2_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(SSG2_0(w[i - 15]))
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

    macro_rules! SHA2_STEP {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$F:ident,$G:ident,$H:ident,$j:expr) => {{
            let t1 = $H
                .wrapping_add(BSG2_1($E))
                .wrapping_add(CH($E, $F, $G))
                .wrapping_add(K[$j])
                .wrapping_add(w[$j]);
            let t2 = BSG2_0($A).wrapping_add(MAJ($A, $B, $C));
            $D = $D.wrapping_add(t1);
            $H = t1.wrapping_add(t2);
        }};
    }

    let mut i = 0;
    while i < 64 {
        SHA2_STEP!(a, b, c, d, e, f, g, h, i + 0);
        SHA2_STEP!(h, a, b, c, d, e, f, g, i + 1);
        SHA2_STEP!(g, h, a, b, c, d, e, f, i + 2);
        SHA2_STEP!(f, g, h, a, b, c, d, e, i + 3);
        SHA2_STEP!(e, f, g, h, a, b, c, d, i + 4);
        SHA2_STEP!(d, e, f, g, h, a, b, c, i + 5);
        SHA2_STEP!(c, d, e, f, g, h, a, b, i + 6);
        SHA2_STEP!(b, c, d, e, f, g, h, a, i + 7);
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

/// SHA-224/SHA-256 context. SHA-224 and SHA-256 share one context type (as in
/// BearSSL); they differ only by the `vtable`/IV set at init and the output
/// truncation derived from the descriptor.
#[derive(Clone)]
pub struct br_sha256_context {
    pub vtable: &'static br_hash_class,
    pub buf: [u8; 64],
    pub count: u64,
    pub val: [u32; 8],
}

/// SHA-224 and SHA-256 use identical contexts.
pub type br_sha224_context = br_sha256_context;

fn sha2small_update(cc: &mut br_sha256_context, data: &[u8], len: usize) {
    let mut ptr = (cc.count & 63) as usize;
    cc.count += len as u64;
    let mut off = 0;
    let mut len = len;
    while len > 0 {
        let mut clen = 64 - ptr;
        if clen > len {
            clen = len;
        }
        cc.buf[ptr..ptr + clen].copy_from_slice(&data[off..off + clen]);
        ptr += clen;
        off += clen;
        len -= clen;
        if ptr == 64 {
            let buf = cc.buf;
            br_sha2small_round(&buf, &mut cc.val);
            ptr = 0;
        }
    }
}

fn sha2small_out(cc: &br_sha256_context, dst: &mut [u8], num: usize) {
    let mut buf = [0u8; 64];
    let mut val = cc.val;
    let mut ptr = (cc.count & 63) as usize;
    buf[..ptr].copy_from_slice(&cc.buf[..ptr]);
    buf[ptr] = 0x80;
    ptr += 1;
    if ptr > 56 {
        // remaining bytes already zero
        br_sha2small_round(&buf, &mut val);
        buf = [0u8; 64];
    } else {
        for b in buf[ptr..56].iter_mut() {
            *b = 0;
        }
    }
    br_enc64be(&mut buf[56..], cc.count << 3);
    br_sha2small_round(&buf, &mut val);
    br_range_enc32be(dst, &val, num);
}

/// see bearssl.h
pub fn br_sha224_init(cc: &mut br_sha224_context) {
    cc.vtable = &br_sha224_vtable;
    cc.val = br_sha224_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_sha224_update(cc: &mut br_sha224_context, data: &[u8], len: usize) {
    sha2small_update(cc, data, len);
}

/// see bearssl.h
pub fn br_sha224_out(cc: &br_sha224_context, dst: &mut [u8]) {
    sha2small_out(cc, dst, 7);
}

/// see bearssl.h
pub fn br_sha224_state(cc: &br_sha224_context, dst: &mut [u8]) -> u64 {
    br_range_enc32be(dst, &cc.val, 8);
    cc.count
}

/// see bearssl.h
pub fn br_sha224_set_state(cc: &mut br_sha224_context, stb: &[u8], count: u64) {
    br_range_dec32be(&mut cc.val, 8, stb);
    cc.count = count;
}

/// see bearssl.h
pub fn br_sha256_init(cc: &mut br_sha256_context) {
    cc.vtable = &br_sha256_vtable;
    cc.val = br_sha256_IV;
    cc.count = 0;
}

pub use br_sha224_set_state as br_sha256_set_state;
pub use br_sha224_state as br_sha256_state;
pub use br_sha224_update as br_sha256_update;

/// see bearssl.h
pub fn br_sha256_out(cc: &br_sha256_context, dst: &mut [u8]) {
    sha2small_out(cc, dst, 8);
}

/// SHA-256's compression function is exposed under its own name too.
pub use br_sha2small_round as br_sha256_round;

impl br_sha256_context {
    fn new_sha224() -> Self {
        let mut cc = br_sha256_context {
            vtable: &br_sha224_vtable,
            buf: [0u8; 64],
            count: 0,
            val: [0u32; 8],
        };
        br_sha224_init(&mut cc);
        cc
    }
    fn new_sha256() -> Self {
        let mut cc = br_sha256_context {
            vtable: &br_sha256_vtable,
            buf: [0u8; 64],
            count: 0,
            val: [0u32; 8],
        };
        br_sha256_init(&mut cc);
        cc
    }
}

impl HashState for br_sha256_context {
    fn vtable(&self) -> &'static br_hash_class {
        self.vtable
    }
    fn update(&mut self, data: &[u8]) {
        sha2small_update(self, data, data.len());
    }
    fn out(&self, dst: &mut [u8]) {
        // Output size (and therefore truncation) is carried by the vtable.
        sha2small_out(self, dst, self.vtable.out_size() / 4);
    }
    fn state(&self, dst: &mut [u8]) -> u64 {
        br_range_enc32be(dst, &self.val, 8);
        self.count
    }
    fn set_state(&mut self, stb: &[u8], count: u64) {
        br_range_dec32be(&mut self.val, 8, stb);
        self.count = count;
    }
}

/// see bearssl.h
pub static br_sha224_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_sha224_context>(),
    desc: BR_HASHDESC_ID(br_sha224_ID)
        | BR_HASHDESC_OUT(28)
        | BR_HASHDESC_STATE(32)
        | BR_HASHDESC_LBLEN(6)
        | BR_HASHDESC_MD_PADDING
        | BR_HASHDESC_MD_PADDING_BE,
    new: || Box::new(br_sha256_context::new_sha224()),
};

/// see bearssl.h
pub static br_sha256_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_sha256_context>(),
    desc: BR_HASHDESC_ID(br_sha256_ID)
        | BR_HASHDESC_OUT(32)
        | BR_HASHDESC_STATE(32)
        | BR_HASHDESC_LBLEN(6)
        | BR_HASHDESC_MD_PADDING
        | BR_HASHDESC_MD_PADDING_BE,
    new: || Box::new(br_sha256_context::new_sha256()),
};
