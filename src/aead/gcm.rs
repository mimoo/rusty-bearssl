/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES-GCM (`src/aead/gcm.c`), built on a CTR block-cipher implementation and a
//! GHASH function. Tracks the C buffering logic exactly (see the C source notes
//! on `buf[]`, `count_aad`, `count_ctr`).

use super::Aead;
use crate::hash::br_ghash;
use crate::inner::{br_dec32be, br_enc64be, EQ0};
use crate::symcipher::Ctr;

/// GCM context. `bctx` is the initialised CTR cipher (e.g. AES-CTR).
pub struct br_gcm_context {
    pub bctx: Box<dyn Ctr>,
    pub gh: br_ghash,
    pub h: [u8; 16],
    pub j0_1: [u8; 12],
    pub buf: [u8; 16],
    pub y: [u8; 16],
    pub j0_2: u32,
    pub jc: u32,
    pub count_aad: u64,
    pub count_ctr: u64,
}

/// see bearssl_aead.h
pub fn br_gcm_init(bctx: Box<dyn Ctr>, gh: br_ghash) -> br_gcm_context {
    let mut ctx = br_gcm_context {
        bctx,
        gh,
        h: [0u8; 16],
        j0_1: [0u8; 12],
        buf: [0u8; 16],
        y: [0u8; 16],
        j0_2: 0,
        jc: 0,
        count_aad: 0,
        count_ctr: 0,
    };
    // The GHASH key h[] is the raw encryption of the all-zero block: CTR with
    // an all-zero IV and counter 0 over a zero block.
    let iv = [0u8; 12];
    ctx.bctx.run(&iv, 0, &mut ctx.h);
    ctx
}

/// see bearssl_aead.h
pub fn br_gcm_reset(ctx: &mut br_gcm_context, iv: &[u8]) {
    let len = iv.len();
    if len == 12 {
        ctx.j0_1.copy_from_slice(&iv[..12]);
        ctx.j0_2 = 1;
    } else {
        let mut ty = [0u8; 16];
        let mut tmp = [0u8; 16];
        (ctx.gh)(&mut ty, &ctx.h, iv);
        br_enc64be(&mut tmp[8..], (len as u64) << 3);
        (ctx.gh)(&mut ty, &ctx.h, &tmp);
        ctx.j0_1.copy_from_slice(&ty[..12]);
        ctx.j0_2 = br_dec32be(&ty[12..]);
    }
    ctx.jc = ctx.j0_2 + 1;
    ctx.y = [0u8; 16];
    ctx.count_aad = 0;
    ctx.count_ctr = 0;
}

/// see bearssl_aead.h
pub fn br_gcm_aad_inject(ctx: &mut br_gcm_context, data: &[u8], len: usize) {
    let mut data = &data[..len];
    let mut len = len;
    let ptr = (ctx.count_aad & 15) as usize;
    if ptr != 0 {
        let clen = 16 - ptr;
        if len < clen {
            ctx.buf[ptr..ptr + len].copy_from_slice(&data[..len]);
            ctx.count_aad += len as u64;
            return;
        }
        ctx.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
        let buf = ctx.buf;
        (ctx.gh)(&mut ctx.y, &ctx.h, &buf);
        data = &data[clen..];
        len -= clen;
        ctx.count_aad += clen as u64;
    }
    let dlen = len & !15;
    (ctx.gh)(&mut ctx.y, &ctx.h, &data[..dlen]);
    ctx.buf[..len - dlen].copy_from_slice(&data[dlen..len]);
    ctx.count_aad += len as u64;
}

/// see bearssl_aead.h
pub fn br_gcm_flip(ctx: &mut br_gcm_context) {
    let ptr = (ctx.count_aad & 15) as usize;
    if ptr != 0 {
        let buf = ctx.buf;
        (ctx.gh)(&mut ctx.y, &ctx.h, &buf[..ptr]);
    }
}

/// see bearssl_aead.h
pub fn br_gcm_run(ctx: &mut br_gcm_context, encrypt: bool, data: &mut [u8], len: usize) {
    let mut off = 0usize;
    let mut len = len;
    let ptr = (ctx.count_ctr & 15) as usize;
    if ptr != 0 {
        let mut clen = 16 - ptr;
        if len < clen {
            clen = len;
        }
        for u in 0..clen {
            let x = data[off + u] as u32;
            let y = x ^ (ctx.buf[ptr + u] as u32);
            ctx.buf[ptr + u] = if encrypt { y as u8 } else { x as u8 };
            data[off + u] = y as u8;
        }
        ctx.count_ctr += clen as u64;
        off += clen;
        len -= clen;
        if ptr + clen < 16 {
            return;
        }
        let buf = ctx.buf;
        (ctx.gh)(&mut ctx.y, &ctx.h, &buf);
    }

    let dlen = len & !15;
    if !encrypt {
        (ctx.gh)(&mut ctx.y, &ctx.h, &data[off..off + dlen]);
    }
    ctx.jc = ctx.bctx.run(&ctx.j0_1, ctx.jc, &mut data[off..off + dlen]);
    if encrypt {
        (ctx.gh)(&mut ctx.y, &ctx.h, &data[off..off + dlen]);
    }
    off += dlen;
    len -= dlen;
    ctx.count_ctr += dlen as u64;

    if len > 0 {
        ctx.buf = [0u8; 16];
        let mut buf = ctx.buf;
        ctx.jc = ctx.bctx.run(&ctx.j0_1, ctx.jc, &mut buf);
        ctx.buf = buf;
        for u in 0..len {
            let x = data[off + u] as u32;
            let y = x ^ (ctx.buf[u] as u32);
            ctx.buf[u] = if encrypt { y as u8 } else { x as u8 };
            data[off + u] = y as u8;
        }
        ctx.count_ctr += len as u64;
    }
}

/// see bearssl_aead.h
pub fn br_gcm_get_tag(ctx: &mut br_gcm_context, tag: &mut [u8]) {
    let ptr = (ctx.count_ctr & 15) as usize;
    if ptr > 0 {
        let buf = ctx.buf;
        (ctx.gh)(&mut ctx.y, &ctx.h, &buf[..ptr]);
    }
    let mut tmp = [0u8; 16];
    br_enc64be(&mut tmp, ctx.count_aad << 3);
    br_enc64be(&mut tmp[8..], ctx.count_ctr << 3);
    (ctx.gh)(&mut ctx.y, &ctx.h, &tmp);
    tag[..16].copy_from_slice(&ctx.y);
    let mut t16 = [0u8; 16];
    t16.copy_from_slice(&tag[..16]);
    ctx.bctx.run(&ctx.j0_1, ctx.j0_2, &mut t16);
    tag[..16].copy_from_slice(&t16);
}

/// see bearssl_aead.h
pub fn br_gcm_get_tag_trunc(ctx: &mut br_gcm_context, tag: &mut [u8], len: usize) {
    let mut tmp = [0u8; 16];
    br_gcm_get_tag(ctx, &mut tmp);
    tag[..len].copy_from_slice(&tmp[..len]);
}

/// see bearssl_aead.h
pub fn br_gcm_check_tag_trunc(ctx: &mut br_gcm_context, tag: &[u8], len: usize) -> u32 {
    let mut tmp = [0u8; 16];
    br_gcm_get_tag(ctx, &mut tmp);
    let mut x = 0u8;
    for u in 0..len {
        x |= tmp[u] ^ tag[u];
    }
    EQ0(x as i32)
}

/// see bearssl_aead.h
pub fn br_gcm_check_tag(ctx: &mut br_gcm_context, tag: &[u8]) -> u32 {
    br_gcm_check_tag_trunc(ctx, tag, 16)
}

impl Aead for br_gcm_context {
    fn tag_size(&self) -> usize {
        16
    }
    fn reset(&mut self, iv: &[u8]) {
        br_gcm_reset(self, iv);
    }
    fn aad_inject(&mut self, data: &[u8]) {
        br_gcm_aad_inject(self, data, data.len());
    }
    fn flip(&mut self) {
        br_gcm_flip(self);
    }
    fn run(&mut self, encrypt: bool, data: &mut [u8]) {
        let n = data.len();
        br_gcm_run(self, encrypt, data, n);
    }
    fn get_tag(&mut self, tag: &mut [u8]) {
        br_gcm_get_tag(self, tag);
    }
    fn get_tag_trunc(&mut self, tag: &mut [u8], len: usize) {
        br_gcm_get_tag_trunc(self, tag, len);
    }
    fn check_tag(&mut self, tag: &[u8]) -> u32 {
        br_gcm_check_tag(self, tag)
    }
    fn check_tag_trunc(&mut self, tag: &[u8], len: usize) -> u32 {
        br_gcm_check_tag_trunc(self, tag, len)
    }
}
