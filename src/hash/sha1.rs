/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! SHA-1 (`src/hash/sha1.c`).

use super::*;
use crate::codec::{br_range_dec32be, br_range_enc32be};
use crate::inner::br_enc64be;

#[inline(always)]
fn F(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}
#[inline(always)]
fn G(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
#[inline(always)]
fn H(b: u32, c: u32, d: u32) -> u32 {
    (d & c) | ((d | c) & b)
}
#[inline(always)]
fn I(b: u32, c: u32, d: u32) -> u32 {
    G(b, c, d)
}
#[inline(always)]
fn ROTL(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

const K1: u32 = 0x5A827999;
const K2: u32 = 0x6ED9EBA1;
const K3: u32 = 0x8F1BBCDC;
const K4: u32 = 0xCA62C1D6;

/// see inner.h
pub static br_sha1_IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// see inner.h
pub fn br_sha1_round(buf: &[u8], val: &mut [u32; 5]) {
    let mut m = [0u32; 80];
    let mut a = val[0];
    let mut b = val[1];
    let mut c = val[2];
    let mut d = val[3];
    let mut e = val[4];
    br_range_dec32be(&mut m, 16, buf);
    for i in 16..80 {
        let x = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
        m[i] = ROTL(x, 1);
    }

    macro_rules! round {
        ($lo:expr, $hi:expr, $fn:ident, $k:expr) => {
            let mut i = $lo;
            while i < $hi {
                e = e
                    .wrapping_add(ROTL(a, 5))
                    .wrapping_add($fn(b, c, d))
                    .wrapping_add($k)
                    .wrapping_add(m[i + 0]);
                b = ROTL(b, 30);
                d = d
                    .wrapping_add(ROTL(e, 5))
                    .wrapping_add($fn(a, b, c))
                    .wrapping_add($k)
                    .wrapping_add(m[i + 1]);
                a = ROTL(a, 30);
                c = c
                    .wrapping_add(ROTL(d, 5))
                    .wrapping_add($fn(e, a, b))
                    .wrapping_add($k)
                    .wrapping_add(m[i + 2]);
                e = ROTL(e, 30);
                b = b
                    .wrapping_add(ROTL(c, 5))
                    .wrapping_add($fn(d, e, a))
                    .wrapping_add($k)
                    .wrapping_add(m[i + 3]);
                d = ROTL(d, 30);
                a = a
                    .wrapping_add(ROTL(b, 5))
                    .wrapping_add($fn(c, d, e))
                    .wrapping_add($k)
                    .wrapping_add(m[i + 4]);
                c = ROTL(c, 30);
                i += 5;
            }
        };
    }

    round!(0, 20, F, K1);
    round!(20, 40, G, K2);
    round!(40, 60, H, K3);
    round!(60, 80, I, K4);

    val[0] = val[0].wrapping_add(a);
    val[1] = val[1].wrapping_add(b);
    val[2] = val[2].wrapping_add(c);
    val[3] = val[3].wrapping_add(d);
    val[4] = val[4].wrapping_add(e);
}

/// SHA-1 context.
#[derive(Clone)]
pub struct br_sha1_context {
    pub vtable: &'static br_hash_class,
    pub buf: [u8; 64],
    pub count: u64,
    pub val: [u32; 5],
}

/// see bearssl.h
pub fn br_sha1_init(cc: &mut br_sha1_context) {
    cc.vtable = &br_sha1_vtable;
    cc.val = br_sha1_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_sha1_update(cc: &mut br_sha1_context, data: &[u8], len: usize) {
    let mut ptr = (cc.count & 63) as usize;
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
        cc.count += clen as u64;
        if ptr == 64 {
            let buf = cc.buf;
            br_sha1_round(&buf, &mut cc.val);
            ptr = 0;
        }
    }
}

/// see bearssl.h
pub fn br_sha1_out(cc: &br_sha1_context, dst: &mut [u8]) {
    let mut buf = [0u8; 64];
    let mut val = cc.val;
    let mut ptr = (cc.count & 63) as usize;
    buf[..ptr].copy_from_slice(&cc.buf[..ptr]);
    buf[ptr] = 0x80;
    ptr += 1;
    if ptr > 56 {
        br_sha1_round(&buf, &mut val);
        buf = [0u8; 64];
    }
    br_enc64be(&mut buf[56..], cc.count << 3);
    br_sha1_round(&buf, &mut val);
    br_range_enc32be(dst, &val, 5);
}

/// see bearssl.h
pub fn br_sha1_state(cc: &br_sha1_context, dst: &mut [u8]) -> u64 {
    br_range_enc32be(dst, &cc.val, 5);
    cc.count
}

/// see bearssl.h
pub fn br_sha1_set_state(cc: &mut br_sha1_context, stb: &[u8], count: u64) {
    br_range_dec32be(&mut cc.val, 5, stb);
    cc.count = count;
}

impl br_sha1_context {
    fn new_ctx() -> Self {
        let mut cc = br_sha1_context {
            vtable: &br_sha1_vtable,
            buf: [0u8; 64],
            count: 0,
            val: [0u32; 5],
        };
        br_sha1_init(&mut cc);
        cc
    }
}

impl HashState for br_sha1_context {
    fn vtable(&self) -> &'static br_hash_class {
        self.vtable
    }
    fn update(&mut self, data: &[u8]) {
        br_sha1_update(self, data, data.len());
    }
    fn out(&self, dst: &mut [u8]) {
        br_sha1_out(self, dst);
    }
    fn state(&self, dst: &mut [u8]) -> u64 {
        br_sha1_state(self, dst)
    }
    fn set_state(&mut self, stb: &[u8], count: u64) {
        br_sha1_set_state(self, stb, count);
    }
}

/// see bearssl.h
pub static br_sha1_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_sha1_context>(),
    desc: BR_HASHDESC_ID(br_sha1_ID)
        | BR_HASHDESC_OUT(20)
        | BR_HASHDESC_STATE(20)
        | BR_HASHDESC_LBLEN(6)
        | BR_HASHDESC_MD_PADDING
        | BR_HASHDESC_MD_PADDING_BE,
    new: || Box::new(br_sha1_context::new_ctx()),
};
