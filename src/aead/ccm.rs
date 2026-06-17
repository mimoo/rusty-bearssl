/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES-CCM (`src/aead/ccm.c`), built on a CTR + CBC-MAC block-cipher class.
//!
//! CCM is MAC-and-encrypt (CBC-MAC over the plaintext), whereas the `CtrCbc`
//! class is encrypt-then-MAC. Because CTR encryption is its own inverse, CCM
//! encryption uses the class's `decrypt` method and CCM decryption uses
//! `encrypt` — exactly as the C source does.

use crate::inner::{br_enc16be, br_enc32be, br_enc64be, EQ0};
use crate::symcipher::CtrCbc;

/// AES-CCM context.
pub struct br_ccm_context {
    pub bctx: Box<dyn CtrCbc>,
    pub ctr: [u8; 16],
    pub cbcmac: [u8; 16],
    pub tagmask: [u8; 16],
    pub buf: [u8; 16],
    pub ptr: usize,
    pub tag_len: usize,
}

/// see bearssl_block.h
pub fn br_ccm_init(bctx: Box<dyn CtrCbc>) -> br_ccm_context {
    br_ccm_context {
        bctx,
        ctr: [0u8; 16],
        cbcmac: [0u8; 16],
        tagmask: [0u8; 16],
        buf: [0u8; 16],
        ptr: 0,
        tag_len: 0,
    }
}

/// see bearssl_block.h
pub fn br_ccm_reset(
    ctx: &mut br_ccm_context,
    nonce: &[u8],
    aad_len: u64,
    mut data_len: u64,
    tag_len: usize,
) -> bool {
    let nonce_len = nonce.len();
    if !(7..=13).contains(&nonce_len) {
        return false;
    }
    if !(4..=16).contains(&tag_len) || (tag_len & 1) != 0 {
        return false;
    }
    let q = 15 - nonce_len;
    ctx.tag_len = tag_len;

    // Block B0, to start CBC-MAC.
    let mut tmp = [0u8; 16];
    tmp[0] = (if aad_len > 0 { 0x40 } else { 0x00 })
        | (((tag_len as u8) - 2) << 2)
        | ((q as u8) - 1);
    tmp[1..1 + nonce_len].copy_from_slice(nonce);
    for u in 0..q {
        tmp[15 - u] = data_len as u8;
        data_len >>= 8;
    }
    if data_len != 0 {
        // Data length exceeds what q bytes can encode.
        return false;
    }

    // Start CBC-MAC.
    ctx.cbcmac = [0u8; 16];
    {
        let cbcmac = &mut ctx.cbcmac;
        ctx.bctx.mac(cbcmac, &tmp);
    }

    // Assemble AAD length header.
    if (aad_len >> 32) != 0 {
        ctx.buf[0] = 0xFF;
        ctx.buf[1] = 0xFF;
        br_enc64be(&mut ctx.buf[2..], aad_len);
        ctx.ptr = 10;
    } else if aad_len >= 0xFF00 {
        ctx.buf[0] = 0xFF;
        ctx.buf[1] = 0xFE;
        br_enc32be(&mut ctx.buf[2..], aad_len as u32);
        ctx.ptr = 6;
    } else if aad_len > 0 {
        br_enc16be(&mut ctx.buf, aad_len as u32);
        ctx.ptr = 2;
    } else {
        ctx.ptr = 0;
    }

    // Initial counter value and tag mask.
    ctx.ctr[0] = (q as u8) - 1;
    ctx.ctr[1..1 + nonce_len].copy_from_slice(nonce);
    for b in ctx.ctr[1 + nonce_len..1 + nonce_len + q].iter_mut() {
        *b = 0;
    }
    ctx.tagmask = [0u8; 16];
    let mut tm = ctx.tagmask;
    ctx.bctx.ctr(&mut ctx.ctr, &mut tm);
    ctx.tagmask = tm;

    true
}

/// see bearssl_block.h
pub fn br_ccm_aad_inject(ctx: &mut br_ccm_context, data: &[u8]) {
    let mut off = 0usize;
    let mut len = data.len();
    let mut ptr = ctx.ptr;
    if ptr != 0 {
        let clen = 16 - ptr;
        if clen > len {
            ctx.buf[ptr..ptr + len].copy_from_slice(&data[..len]);
            ctx.ptr = ptr + len;
            return;
        }
        ctx.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
        off += clen;
        len -= clen;
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
    }
    ptr = len & 15;
    len -= ptr;
    ctx.bctx.mac(&mut ctx.cbcmac, &data[off..off + len]);
    off += len;
    ctx.buf[..ptr].copy_from_slice(&data[off..off + ptr]);
    ctx.ptr = ptr;
}

/// see bearssl_block.h
pub fn br_ccm_flip(ctx: &mut br_ccm_context) {
    let ptr = ctx.ptr;
    if ptr != 0 {
        for b in ctx.buf[ptr..16].iter_mut() {
            *b = 0;
        }
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
        ctx.ptr = 0;
    }
}

/// see bearssl_block.h
pub fn br_ccm_run(ctx: &mut br_ccm_context, encrypt: bool, data: &mut [u8]) {
    let mut off = 0usize;
    let mut len = data.len();
    let mut ptr = ctx.ptr;
    if ptr != 0 {
        let mut clen = 16 - ptr;
        if clen > len {
            clen = len;
        }
        if encrypt {
            for u in 0..clen {
                let w = ctx.buf[ptr + u];
                let x = data[off + u];
                ctx.buf[ptr + u] = x;
                data[off + u] = w ^ x;
            }
        } else {
            for u in 0..clen {
                let w = ctx.buf[ptr + u] ^ data[off + u];
                data[off + u] = w;
                ctx.buf[ptr + u] = w;
            }
        }
        off += clen;
        len -= clen;
        ptr += clen;
        if ptr < 16 {
            ctx.ptr = ptr;
            return;
        }
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
    }

    // Full blocks. CCM is MAC-and-encrypt, so swap encrypt/decrypt (see note).
    ptr = len & 15;
    len -= ptr;
    {
        let mut ctr = ctx.ctr;
        let mut cbcmac = ctx.cbcmac;
        if encrypt {
            ctx.bctx.decrypt(&mut ctr, &mut cbcmac, &mut data[off..off + len]);
        } else {
            ctx.bctx.encrypt(&mut ctr, &mut cbcmac, &mut data[off..off + len]);
        }
        ctx.ctr = ctr;
        ctx.cbcmac = cbcmac;
    }
    off += len;

    if ptr != 0 {
        ctx.buf = [0u8; 16];
        let mut ctr = ctx.ctr;
        let mut buf = ctx.buf;
        ctx.bctx.ctr(&mut ctr, &mut buf);
        ctx.ctr = ctr;
        ctx.buf = buf;
        if encrypt {
            for u in 0..ptr {
                let w = ctx.buf[u];
                let x = data[off + u];
                ctx.buf[u] = x;
                data[off + u] = w ^ x;
            }
        } else {
            for u in 0..ptr {
                let w = ctx.buf[u] ^ data[off + u];
                data[off + u] = w;
                ctx.buf[u] = w;
            }
        }
    }
    ctx.ptr = ptr;
}

/// see bearssl_block.h
pub fn br_ccm_get_tag(ctx: &mut br_ccm_context, tag: &mut [u8]) -> usize {
    let ptr = ctx.ptr;
    if ptr != 0 {
        for b in ctx.buf[ptr..16].iter_mut() {
            *b = 0;
        }
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
    }
    for u in 0..ctx.tag_len {
        ctx.cbcmac[u] ^= ctx.tagmask[u];
    }
    tag[..ctx.tag_len].copy_from_slice(&ctx.cbcmac[..ctx.tag_len]);
    ctx.tag_len
}

/// see bearssl_block.h
pub fn br_ccm_check_tag(ctx: &mut br_ccm_context, tag: &[u8]) -> u32 {
    let mut tmp = [0u8; 16];
    let tl = br_ccm_get_tag(ctx, &mut tmp);
    let mut z = 0u8;
    for u in 0..tl {
        z |= tmp[u] ^ tag[u];
    }
    EQ0(z as i32)
}
