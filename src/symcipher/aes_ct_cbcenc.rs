/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES-ct CBC encryption (`src/symcipher/aes_ct_cbcenc.c`).

use super::aes_ct::{br_aes_ct_keysched, br_aes_ct_ortho, br_aes_ct_skey_expand};
use super::aes_ct_enc::br_aes_ct_bitslice_encrypt;
use super::{br_block_cbcenc_class, CbcEnc};
use crate::inner::{br_dec32le, br_enc32le};

/// see bearssl_block.h (`br_aes_ct_cbcenc_keys`)
#[derive(Clone)]
pub struct br_aes_ct_cbcenc_keys {
    pub skey: [u32; 60],
    pub num_rounds: u32,
}

impl br_aes_ct_cbcenc_keys {
    fn zeroed() -> Self {
        br_aes_ct_cbcenc_keys {
            skey: [0u32; 60],
            num_rounds: 0,
        }
    }
}

/// see bearssl_block.h
pub fn br_aes_ct_cbcenc_init(ctx: &mut br_aes_ct_cbcenc_keys, key: &[u8]) {
    ctx.num_rounds = br_aes_ct_keysched(&mut ctx.skey, key);
}

/// see bearssl_block.h
pub fn br_aes_ct_cbcenc_run(ctx: &br_aes_ct_cbcenc_keys, iv: &mut [u8], data: &mut [u8]) {
    let mut q = [0u32; 8];
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);
    let mut iv0 = br_dec32le(iv);
    let mut iv1 = br_dec32le(&iv[4..]);
    let mut iv2 = br_dec32le(&iv[8..]);
    let mut iv3 = br_dec32le(&iv[12..]);
    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        q[0] = iv0 ^ br_dec32le(&data[off..]);
        q[2] = iv1 ^ br_dec32le(&data[off + 4..]);
        q[4] = iv2 ^ br_dec32le(&data[off + 8..]);
        q[6] = iv3 ^ br_dec32le(&data[off + 12..]);
        br_aes_ct_ortho(&mut q);
        br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
        br_aes_ct_ortho(&mut q);
        iv0 = q[0];
        iv1 = q[2];
        iv2 = q[4];
        iv3 = q[6];
        br_enc32le(&mut data[off..], iv0);
        br_enc32le(&mut data[off + 4..], iv1);
        br_enc32le(&mut data[off + 8..], iv2);
        br_enc32le(&mut data[off + 12..], iv3);
        off += 16;
        len -= 16;
    }
    br_enc32le(iv, iv0);
    br_enc32le(&mut iv[4..], iv1);
    br_enc32le(&mut iv[8..], iv2);
    br_enc32le(&mut iv[12..], iv3);
}

impl CbcEnc for br_aes_ct_cbcenc_keys {
    fn run(&self, iv: &mut [u8], data: &mut [u8]) {
        br_aes_ct_cbcenc_run(self, iv, data);
    }
}

/// see bearssl_block.h
pub static br_aes_ct_cbcenc_vtable: br_block_cbcenc_class = br_block_cbcenc_class {
    context_size: std::mem::size_of::<br_aes_ct_cbcenc_keys>(),
    block_size: 16,
    log_block_size: 4,
    init: |key| {
        let mut ctx = br_aes_ct_cbcenc_keys::zeroed();
        br_aes_ct_cbcenc_init(&mut ctx, key);
        Box::new(ctx)
    },
};
