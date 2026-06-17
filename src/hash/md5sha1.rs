/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! MD5+SHA-1 combined hash for the TLS 1.0/1.1 PRF (`src/hash/md5sha1.c`).

use super::md5::{br_md5_round, br_md5_IV};
use super::sha1::{br_sha1_round, br_sha1_IV};
use super::*;
use crate::codec::{br_range_dec32be, br_range_dec32le, br_range_enc32be, br_range_enc32le};
use crate::inner::{br_enc64be, br_enc64le};

/// MD5+SHA-1 context.
#[derive(Clone)]
pub struct br_md5sha1_context {
    pub vtable: &'static br_hash_class,
    pub buf: [u8; 64],
    pub count: u64,
    pub val_md5: [u32; 4],
    pub val_sha1: [u32; 5],
}

/// see bearssl.h
pub fn br_md5sha1_init(cc: &mut br_md5sha1_context) {
    cc.vtable = &br_md5sha1_vtable;
    cc.val_md5 = br_md5_IV;
    cc.val_sha1 = br_sha1_IV;
    cc.count = 0;
}

/// see bearssl.h
pub fn br_md5sha1_update(cc: &mut br_md5sha1_context, data: &[u8], len: usize) {
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
            br_md5_round(&buf, &mut cc.val_md5);
            br_sha1_round(&buf, &mut cc.val_sha1);
            ptr = 0;
        }
    }
}

/// see bearssl.h
pub fn br_md5sha1_out(cc: &br_md5sha1_context, dst: &mut [u8]) {
    let mut buf = [0u8; 64];
    let mut val_md5 = cc.val_md5;
    let mut val_sha1 = cc.val_sha1;
    let count = cc.count;
    let mut ptr = (count & 63) as usize;
    buf[..ptr].copy_from_slice(&cc.buf[..ptr]);
    buf[ptr] = 0x80;
    ptr += 1;
    if ptr > 56 {
        br_md5_round(&buf, &mut val_md5);
        br_sha1_round(&buf, &mut val_sha1);
        buf = [0u8; 64];
    }
    let count = count << 3;
    br_enc64le(&mut buf[56..], count);
    br_md5_round(&buf, &mut val_md5);
    br_enc64be(&mut buf[56..], count);
    br_sha1_round(&buf, &mut val_sha1);
    br_range_enc32le(dst, &val_md5, 4);
    br_range_enc32be(&mut dst[16..], &val_sha1, 5);
}

/// see bearssl.h
pub fn br_md5sha1_state(cc: &br_md5sha1_context, dst: &mut [u8]) -> u64 {
    br_range_enc32le(dst, &cc.val_md5, 4);
    br_range_enc32be(&mut dst[16..], &cc.val_sha1, 5);
    cc.count
}

/// see bearssl.h
pub fn br_md5sha1_set_state(cc: &mut br_md5sha1_context, stb: &[u8], count: u64) {
    br_range_dec32le(&mut cc.val_md5, 4, stb);
    br_range_dec32be(&mut cc.val_sha1, 5, &stb[16..]);
    cc.count = count;
}

impl br_md5sha1_context {
    fn new_ctx() -> Self {
        let mut cc = br_md5sha1_context {
            vtable: &br_md5sha1_vtable,
            buf: [0u8; 64],
            count: 0,
            val_md5: [0u32; 4],
            val_sha1: [0u32; 5],
        };
        br_md5sha1_init(&mut cc);
        cc
    }
}

impl HashState for br_md5sha1_context {
    fn vtable(&self) -> &'static br_hash_class {
        self.vtable
    }
    fn update(&mut self, data: &[u8]) {
        br_md5sha1_update(self, data, data.len());
    }
    fn out(&self, dst: &mut [u8]) {
        br_md5sha1_out(self, dst);
    }
    fn state(&self, dst: &mut [u8]) -> u64 {
        br_md5sha1_state(self, dst)
    }
    fn set_state(&mut self, stb: &[u8], count: u64) {
        br_md5sha1_set_state(self, stb, count);
    }
}

/// see bearssl.h
pub static br_md5sha1_vtable: br_hash_class = br_hash_class {
    context_size: std::mem::size_of::<br_md5sha1_context>(),
    desc: BR_HASHDESC_ID(br_md5sha1_ID)
        | BR_HASHDESC_OUT(36)
        | BR_HASHDESC_STATE(36)
        | BR_HASHDESC_LBLEN(6),
    new: || Box::new(br_md5sha1_context::new_ctx()),
};
