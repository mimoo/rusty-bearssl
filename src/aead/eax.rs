/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! EAX (`src/aead/eax.c`), built on the CTR + CBC-MAC block-cipher class.
//!
//! EAX is encrypt-then-MAC, computing three OMAC (a.k.a. CMAC) tags over the
//! nonce, the additional authenticated data, and the ciphertext, then XORing
//! them together. The combined CTR + CBC-MAC functions can only handle full
//! blocks, so buffering is needed; moreover, EAX's OMAC padding rule means the
//! last full block cannot be processed until we know whether it is the last
//! one. See the implementation notes in the C source.

use super::Aead;
use crate::inner::EQ0;
use crate::symcipher::CtrCbc;

/// EAX context (`br_eax_context`).
pub struct br_eax_context {
    pub bctx: Box<dyn CtrCbc>,
    pub L2: [u8; 16],
    pub L4: [u8; 16],
    pub nonce: [u8; 16],
    pub head: [u8; 16],
    pub ctr: [u8; 16],
    pub cbcmac: [u8; 16],
    pub buf: [u8; 16],
    pub ptr: usize,
}

/// Captured EAX state for nonce/AAD pre-processing (`br_eax_state`).
#[derive(Clone, Copy)]
pub struct br_eax_state {
    pub st: [[u8; 16]; 3],
}

impl Default for br_eax_state {
    fn default() -> Self {
        br_eax_state { st: [[0u8; 16]; 3] }
    }
}

/// Start an OMAC computation; the first block is the big-endian representation
/// of the provided value (`val` must fit on one byte). We make it a delayed
/// block because it may also be the last one.
fn omac_start(ctx: &mut br_eax_context, val: u8) {
    ctx.cbcmac = [0u8; 16];
    ctx.buf = [0u8; 16];
    ctx.buf[15] = val;
    ctx.ptr = 16;
}

/// Double a value in finite field GF(2^128), defined with modulus
/// X^128+X^7+X^2+X+1.
fn double_gf128(dst: &mut [u8; 16], src: &[u8; 16]) {
    let mut cc = 0x87u32 & (0u32.wrapping_sub((src[0] as u32) >> 7));
    for i in (0..16).rev() {
        let z = ((src[i] as u32) << 1) ^ cc;
        cc = z >> 8;
        dst[i] = z as u8;
    }
}

/// Apply padding to the last block, currently in ctx.buf (with ctx.ptr bytes),
/// and finalize the OMAC computation.
fn do_pad(ctx: &mut br_eax_context) {
    let mut ptr = ctx.ptr;
    let pad = if ptr == 16 {
        ctx.L2
    } else {
        ctx.buf[ptr] = 0x80;
        ptr += 1;
        for b in ctx.buf[ptr..16].iter_mut() {
            *b = 0x00;
        }
        ctx.L4
    };
    for u in 0..16 {
        ctx.buf[u] ^= pad[u];
    }
    let buf = ctx.buf;
    ctx.bctx.mac(&mut ctx.cbcmac, &buf);
}

/// Apply CBC-MAC on the provided data, with buffering management.
///
/// Upon entry, two situations are acceptable:
///   ctx.ptr == 0: there is no data to process in ctx.buf
///   ctx.ptr == 16: there is a full block of unprocessed data in ctx.buf
///
/// Upon exit, ctx.ptr may be zero only if it was already zero on entry, and
/// len == 0. In all other situations, ctx.ptr will be non-zero on exit (and may
/// have value 16).
fn do_cbcmac_chunk(ctx: &mut br_eax_context, data: &[u8]) {
    let mut len = data.len();
    if len == 0 {
        return;
    }
    let mut ptr = len & 15;
    if ptr == 0 {
        len -= 16;
        ptr = 16;
    } else {
        len -= ptr;
    }
    if ctx.ptr == 16 {
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
    }
    ctx.bctx.mac(&mut ctx.cbcmac, &data[..len]);
    ctx.buf[..ptr].copy_from_slice(&data[len..len + ptr]);
    ctx.ptr = ptr;
}

/// see bearssl_aead.h
pub fn br_eax_init(bctx: Box<dyn CtrCbc>) -> br_eax_context {
    let mut ctx = br_eax_context {
        bctx,
        L2: [0u8; 16],
        L4: [0u8; 16],
        nonce: [0u8; 16],
        head: [0u8; 16],
        ctr: [0u8; 16],
        cbcmac: [0u8; 16],
        buf: [0u8; 16],
        ptr: 0,
    };

    // Encrypt a whole-zero block to compute L2 and L4.
    let mut tmp = [0u8; 16];
    let mut iv = [0u8; 16];
    ctx.bctx.ctr(&mut iv, &mut tmp);
    let mut l2 = [0u8; 16];
    double_gf128(&mut l2, &tmp);
    ctx.L2 = l2;
    let mut l4 = [0u8; 16];
    double_gf128(&mut l4, &l2);
    ctx.L4 = l4;
    ctx
}

/// see bearssl_aead.h
pub fn br_eax_capture(ctx: &br_eax_context, st: &mut br_eax_state) {
    // We capture the three OMAC* states _after_ processing the initial block
    // (assuming that nonce, message and AAD are all non-empty).
    st.st = [[0u8; 16]; 3];
    for i in 0..3 {
        let mut tmp = [0u8; 16];
        tmp[15] = i as u8;
        ctx.bctx.mac(&mut st.st[i], &tmp);
    }
}

/// see bearssl_aead.h
pub fn br_eax_reset(ctx: &mut br_eax_context, nonce: &[u8]) {
    // Process nonce with OMAC^0.
    omac_start(ctx, 0);
    do_cbcmac_chunk(ctx, nonce);
    do_pad(ctx);
    ctx.nonce = ctx.cbcmac;

    // Start OMAC^1 for the AAD ("header" in the EAX specification).
    omac_start(ctx, 1);

    // We use ctx.head[0] as a temporary flag to mark that we are using a
    // "normal" reset().
    ctx.head[0] = 0;
}

/// see bearssl_aead.h
pub fn br_eax_reset_pre_aad(ctx: &mut br_eax_context, st: &br_eax_state, nonce: &[u8]) {
    if nonce.is_empty() {
        omac_start(ctx, 0);
    } else {
        ctx.cbcmac = st.st[0];
        ctx.ptr = 0;
        do_cbcmac_chunk(ctx, nonce);
    }
    do_pad(ctx);
    ctx.nonce = ctx.cbcmac;

    ctx.cbcmac = st.st[1];
    ctx.ptr = 0;

    ctx.ctr = st.st[2];

    // We use ctx.head[0] as a flag to indicate that we use a recorded state,
    // with ctx.ctr containing the preprocessed first block for OMAC^2.
    ctx.head[0] = 1;
}

/// see bearssl_aead.h
pub fn br_eax_reset_post_aad(ctx: &mut br_eax_context, st: &br_eax_state, nonce: &[u8]) {
    if nonce.is_empty() {
        omac_start(ctx, 0);
    } else {
        ctx.cbcmac = st.st[0];
        ctx.ptr = 0;
        do_cbcmac_chunk(ctx, nonce);
    }
    do_pad(ctx);
    ctx.nonce = ctx.cbcmac;
    ctx.ctr = ctx.nonce;

    ctx.head = st.st[1];

    ctx.cbcmac = st.st[2];
    ctx.ptr = 0;
}

/// see bearssl_aead.h
pub fn br_eax_aad_inject(ctx: &mut br_eax_context, data: &[u8]) {
    let ptr = ctx.ptr;
    let mut off = 0usize;
    let mut len = data.len();

    // If there is a partial block, first complete it.
    if ptr < 16 {
        let clen = 16 - ptr;
        if len <= clen {
            ctx.buf[ptr..ptr + len].copy_from_slice(&data[..len]);
            ctx.ptr = ptr + len;
            return;
        }
        ctx.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
        off += clen;
        len -= clen;
    }

    // We now have a full block in buf[], and this is not the last block.
    do_cbcmac_chunk(ctx, &data[off..off + len]);
}

/// see bearssl_aead.h
pub fn br_eax_flip(ctx: &mut br_eax_context) {
    // ctx.head[0] may be non-zero if the context was reset with a pre-AAD
    // captured state. In that case, ctx.ctr[] contains the state for OMAC^2
    // _after_ processing the first block.
    let from_capture = ctx.head[0];

    // Complete the OMAC computation on the AAD.
    do_pad(ctx);
    ctx.head = ctx.cbcmac;

    // Start OMAC^2 for the encrypted data. If the context was initialized from
    // a captured state, then the OMAC^2 value is in the ctr[] array.
    if from_capture != 0 {
        ctx.cbcmac = ctx.ctr;
        ctx.ptr = 0;
    } else {
        omac_start(ctx, 2);
    }

    // Initial counter value for CTR is the processed nonce.
    ctx.ctr = ctx.nonce;
}

/// see bearssl_aead.h
pub fn br_eax_run(ctx: &mut br_eax_context, encrypt: bool, data: &mut [u8]) {
    // Ensure that there is actual data to process.
    if data.is_empty() {
        return;
    }

    let mut off = 0usize;
    let mut len = data.len();
    let mut ptr = ctx.ptr;

    // We may have ptr == 0 here if we initialized from a captured state. In
    // that case, there is no partially consumed block or unprocessed data.
    if ptr != 0 && ptr != 16 {
        // We have a partially consumed block.
        let mut clen = 16 - ptr;
        if len <= clen {
            clen = len;
        }
        if encrypt {
            for u in 0..clen {
                ctx.buf[ptr + u] ^= data[off + u];
            }
            data[off..off + clen].copy_from_slice(&ctx.buf[ptr..ptr + clen]);
        } else {
            for u in 0..clen {
                let sx = ctx.buf[ptr + u];
                let dx = data[off + u];
                ctx.buf[ptr + u] = dx;
                data[off + u] = sx ^ dx;
            }
        }

        if len <= clen {
            ctx.ptr = ptr + clen;
            return;
        }
        off += clen;
        len -= clen;
    }

    // We now have a complete encrypted block in buf[] that must still be
    // processed with OMAC, and this is not the final buf. Exception: when
    // ptr == 0, no block has been produced yet.
    if ptr != 0 {
        let buf = ctx.buf;
        ctx.bctx.mac(&mut ctx.cbcmac, &buf);
    }

    // Do CTR encryption or decryption and CBC-MAC for all full blocks except
    // the last.
    ptr = len & 15;
    if ptr == 0 {
        len -= 16;
        ptr = 16;
    } else {
        len -= ptr;
    }
    {
        let mut ctr = ctx.ctr;
        let mut cbcmac = ctx.cbcmac;
        if encrypt {
            ctx.bctx.encrypt(&mut ctr, &mut cbcmac, &mut data[off..off + len]);
        } else {
            ctx.bctx.decrypt(&mut ctr, &mut cbcmac, &mut data[off..off + len]);
        }
        ctx.ctr = ctr;
        ctx.cbcmac = cbcmac;
    }
    off += len;

    // Compute next block of CTR stream, and use it to finish encrypting or
    // decrypting the data.
    ctx.buf = [0u8; 16];
    {
        let mut ctr = ctx.ctr;
        let mut buf = ctx.buf;
        ctx.bctx.ctr(&mut ctr, &mut buf);
        ctx.ctr = ctr;
        ctx.buf = buf;
    }
    if encrypt {
        for u in 0..ptr {
            ctx.buf[u] ^= data[off + u];
        }
        data[off..off + ptr].copy_from_slice(&ctx.buf[..ptr]);
    } else {
        for u in 0..ptr {
            let sx = ctx.buf[u];
            let dx = data[off + u];
            ctx.buf[u] = dx;
            data[off + u] = sx ^ dx;
        }
    }
    ctx.ptr = ptr;
}

/// Complete tag computation. The final tag is written in ctx.cbcmac.
fn do_final(ctx: &mut br_eax_context) {
    do_pad(ctx);

    // Authentication tag is the XOR of the three OMAC outputs for the nonce,
    // AAD and encrypted data.
    for u in 0..16 {
        ctx.cbcmac[u] ^= ctx.nonce[u] ^ ctx.head[u];
    }
}

/// see bearssl_aead.h
pub fn br_eax_get_tag(ctx: &mut br_eax_context, tag: &mut [u8]) {
    do_final(ctx);
    tag[..16].copy_from_slice(&ctx.cbcmac);
}

/// see bearssl_aead.h
pub fn br_eax_get_tag_trunc(ctx: &mut br_eax_context, tag: &mut [u8], len: usize) {
    do_final(ctx);
    tag[..len].copy_from_slice(&ctx.cbcmac[..len]);
}

/// see bearssl_aead.h
pub fn br_eax_check_tag_trunc(ctx: &mut br_eax_context, tag: &[u8], len: usize) -> u32 {
    let mut tmp = [0u8; 16];
    br_eax_get_tag(ctx, &mut tmp);
    let mut x = 0u8;
    for u in 0..len {
        x |= tmp[u] ^ tag[u];
    }
    EQ0(x as i32)
}

/// see bearssl_aead.h
pub fn br_eax_check_tag(ctx: &mut br_eax_context, tag: &[u8]) -> u32 {
    br_eax_check_tag_trunc(ctx, tag, 16)
}

impl Aead for br_eax_context {
    fn tag_size(&self) -> usize {
        16
    }
    fn reset(&mut self, iv: &[u8]) {
        br_eax_reset(self, iv);
    }
    fn aad_inject(&mut self, data: &[u8]) {
        br_eax_aad_inject(self, data);
    }
    fn flip(&mut self) {
        br_eax_flip(self);
    }
    fn run(&mut self, encrypt: bool, data: &mut [u8]) {
        br_eax_run(self, encrypt, data);
    }
    fn get_tag(&mut self, tag: &mut [u8]) {
        br_eax_get_tag(self, tag);
    }
    fn get_tag_trunc(&mut self, tag: &mut [u8], len: usize) {
        br_eax_get_tag_trunc(self, tag, len);
    }
    fn check_tag(&mut self, tag: &[u8]) -> u32 {
        br_eax_check_tag(self, tag)
    }
    fn check_tag_trunc(&mut self, tag: &[u8], len: usize) -> u32 {
        br_eax_check_tag_trunc(self, tag, len)
    }
}
