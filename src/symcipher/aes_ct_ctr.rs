/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES-ct CTR mode (`src/symcipher/aes_ct_ctr.c`).

use super::aes_ct::{br_aes_ct_keysched, br_aes_ct_ortho, br_aes_ct_skey_expand};
use super::aes_ct_enc::br_aes_ct_bitslice_encrypt;
use super::{br_block_ctr_class, Ctr};
use crate::inner::{br_dec32le, br_enc32le, br_swap32};

/// see bearssl_block.h (`br_aes_ct_ctr_keys`)
#[derive(Clone)]
pub struct br_aes_ct_ctr_keys {
    pub skey: [u32; 60],
    pub num_rounds: u32,
}

impl br_aes_ct_ctr_keys {
    fn zeroed() -> Self {
        br_aes_ct_ctr_keys {
            skey: [0u32; 60],
            num_rounds: 0,
        }
    }
}

/// see bearssl_block.h
pub fn br_aes_ct_ctr_init(ctx: &mut br_aes_ct_ctr_keys, key: &[u8]) {
    ctx.num_rounds = br_aes_ct_keysched(&mut ctx.skey, key);
}

fn xorbuf(dst: &mut [u8], src: &[u8], len: usize) {
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

/// see bearssl_block.h
pub fn br_aes_ct_ctr_run(
    ctx: &br_aes_ct_ctr_keys,
    iv: &[u8],
    mut cc: u32,
    data: &mut [u8],
) -> u32 {
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);
    let iv0 = br_dec32le(iv);
    let iv1 = br_dec32le(&iv[4..]);
    let iv2 = br_dec32le(&iv[8..]);
    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        let mut q = [0u32; 8];
        let mut tmp = [0u8; 32];

        q[0] = iv0;
        q[1] = iv0;
        q[2] = iv1;
        q[3] = iv1;
        q[4] = iv2;
        q[5] = iv2;
        q[6] = br_swap32(cc);
        q[7] = br_swap32(cc.wrapping_add(1));
        br_aes_ct_ortho(&mut q);
        br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
        br_aes_ct_ortho(&mut q);
        br_enc32le(&mut tmp, q[0]);
        br_enc32le(&mut tmp[4..], q[2]);
        br_enc32le(&mut tmp[8..], q[4]);
        br_enc32le(&mut tmp[12..], q[6]);
        br_enc32le(&mut tmp[16..], q[1]);
        br_enc32le(&mut tmp[20..], q[3]);
        br_enc32le(&mut tmp[24..], q[5]);
        br_enc32le(&mut tmp[28..], q[7]);

        if len <= 32 {
            xorbuf(&mut data[off..], &tmp, len);
            cc = cc.wrapping_add(1);
            if len > 16 {
                cc = cc.wrapping_add(1);
            }
            break;
        }
        xorbuf(&mut data[off..], &tmp, 32);
        off += 32;
        len -= 32;
        cc = cc.wrapping_add(2);
    }
    cc
}

impl Ctr for br_aes_ct_ctr_keys {
    fn run(&self, iv: &[u8], cc: u32, data: &mut [u8]) -> u32 {
        br_aes_ct_ctr_run(self, iv, cc, data)
    }
}

/// see bearssl_block.h
pub static br_aes_ct_ctr_vtable: br_block_ctr_class = br_block_ctr_class {
    context_size: std::mem::size_of::<br_aes_ct_ctr_keys>(),
    block_size: 16,
    log_block_size: 4,
    init: |key| {
        let mut ctx = br_aes_ct_ctr_keys::zeroed();
        br_aes_ct_ctr_init(&mut ctx, key);
        Box::new(ctx)
    },
};
