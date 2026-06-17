/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! MD5 (`src/hash/md5.c`).

use super::*;
use crate::codec::{br_range_dec32le, br_range_enc32le};
use crate::inner::br_enc64le;

#[inline(always)]
fn F(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}
#[inline(always)]
fn G(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ b) & d) ^ c
}
#[inline(always)]
fn H(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
#[inline(always)]
fn I(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | !d)
}
#[inline(always)]
fn ROTL(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// see inner.h
pub static br_md5_IV: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];

static K: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

static MP: [u8; 48] = [
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9,
    12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
];

/// see inner.h
pub fn br_md5_round(buf: &[u8], val: &mut [u32; 4]) {
    let mut m = [0u32; 16];
    let mut a = val[0];
    let mut b = val[1];
    let mut c = val[2];
    let mut d = val[3];
    br_range_dec32le(&mut m, 16, buf);

    macro_rules! step {
        ($a:ident, $fn:ident, $b:ident, $c:ident, $d:ident, $mi:expr, $ki:expr, $s:expr) => {
            $a = $b.wrapping_add(ROTL(
                $a.wrapping_add($fn($b, $c, $d))
                    .wrapping_add(m[$mi])
                    .wrapping_add(K[$ki]),
                $s,
            ));
        };
    }

    let mut i = 0;
    while i < 16 {
        step!(a, F, b, c, d, i + 0, i + 0, 7);
        step!(d, F, a, b, c, i + 1, i + 1, 12);
        step!(c, F, d, a, b, i + 2, i + 2, 17);
        step!(b, F, c, d, a, i + 3, i + 3, 22);
        i += 4;
    }
    let mut i = 16;
    while i < 32 {
        step!(a, G, b, c, d, MP[i - 16] as usize, i + 0, 5);
        step!(d, G, a, b, c, MP[i - 15] as usize, i + 1, 9);
        step!(c, G, d, a, b, MP[i - 14] as usize, i + 2, 14);
        step!(b, G, c, d, a, MP[i - 13] as usize, i + 3, 20);
        i += 4;
    }
    let mut i = 32;
    while i < 48 {
        step!(a, H, b, c, d, MP[i - 16] as usize, i + 0, 4);
        step!(d, H, a, b, c, MP[i - 15] as usize, i + 1, 11);
        step!(c, H, d, a, b, MP[i - 14] as usize, i + 2, 16);
        step!(b, H, c, d, a, MP[i - 13] as usize, i + 3, 23);
        i += 4;
    }
    let mut i = 48;
    while i < 64 {
        step!(a, I, b, c, d, MP[i - 16] as usize, i + 0, 6);
        step!(d, I, a, b, c, MP[i - 15] as usize, i + 1, 10);
        step!(c, I, d, a, b, MP[i - 14] as usize, i + 2, 15);
        step!(b, I, c, d, a, MP[i - 13] as usize, i + 3, 21);
        i += 4;
    }

    val[0] = val[0].wrapping_add(a);
    val[1] = val[1].wrapping_add(b);
    val[2] = val[2].wrapping_add(c);
    val[3] = val[3].wrapping_add(d);
}

/// MD5 context.
#[derive(Clone)]
pub struct br_md5_context {
    pub vtable: &'static br_hash_class,
    pub buf: [u8; 64],
    pub count: u64,
    pub val: [u32; 4],
}

/// see bearssl.h
pub fn br_md5_init(cc: &mut br_md5_context) {
    cc.vtable = &br_md5_vtable;
    cc.val = br_md5_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_md5_update(cc: &mut br_md5_context, data: &[u8], len: usize) {
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
            br_md5_round(&buf, &mut cc.val);
            ptr = 0;
        }
    }
}

/// see bearssl.h
pub fn br_md5_out(cc: &br_md5_context, dst: &mut [u8]) {
    let mut buf = [0u8; 64];
    let mut val = cc.val;
    let mut ptr = (cc.count & 63) as usize;
    buf[..ptr].copy_from_slice(&cc.buf[..ptr]);
    buf[ptr] = 0x80;
    ptr += 1;
    if ptr > 56 {
        br_md5_round(&buf, &mut val);
        buf = [0u8; 64];
    }
    br_enc64le(&mut buf[56..], cc.count << 3);
    br_md5_round(&buf, &mut val);
    br_range_enc32le(dst, &val, 4);
}

/// see bearssl.h
pub fn br_md5_state(cc: &br_md5_context, dst: &mut [u8]) -> u64 {
    br_range_enc32le(dst, &cc.val, 4);
    cc.count
}

/// see bearssl.h
pub fn br_md5_set_state(cc: &mut br_md5_context, stb: &[u8], count: u64) {
    br_range_dec32le(&mut cc.val, 4, stb);
    cc.count = count;
}

impl br_md5_context {
    fn new_ctx() -> Self {
        let mut cc = br_md5_context {
            vtable: &br_md5_vtable,
            buf: [0u8; 64],
            count: 0,
            val: [0u32; 4],
        };
        br_md5_init(&mut cc);
        cc
    }
}

impl HashState for br_md5_context {
    fn vtable(&self) -> &'static br_hash_class {
        self.vtable
    }
    fn update(&mut self, data: &[u8]) {
        br_md5_update(self, data, data.len());
    }
    fn out(&self, dst: &mut [u8]) {
        br_md5_out(self, dst);
    }
    fn state(&self, dst: &mut [u8]) -> u64 {
        br_md5_state(self, dst)
    }
    fn set_state(&mut self, stb: &[u8], count: u64) {
        br_md5_set_state(self, stb, count);
    }
}

/// see bearssl.h
pub static br_md5_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_md5_context>(),
    desc: BR_HASHDESC_ID(br_md5_ID)
        | BR_HASHDESC_OUT(16)
        | BR_HASHDESC_STATE(16)
        | BR_HASHDESC_LBLEN(6)
        | BR_HASHDESC_MD_PADDING,
    new: || Box::new(br_md5_context::new_ctx()),
};
