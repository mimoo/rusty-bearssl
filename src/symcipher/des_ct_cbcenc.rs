/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Constant-time DES/3DES CBC encryption (`src/symcipher/des_ct_cbcenc.c`).

use super::des_ct::{br_des_ct_keysched, br_des_ct_process_block, br_des_ct_skey_expand};
use super::{br_block_cbcenc_class, CbcEnc};

/// see bearssl_block.h (`br_des_ct_cbcenc_keys`)
#[derive(Clone)]
pub struct br_des_ct_cbcenc_keys {
    pub skey: [u32; 96],
    pub num_rounds: u32,
}

impl br_des_ct_cbcenc_keys {
    fn zeroed() -> Self {
        br_des_ct_cbcenc_keys {
            skey: [0u32; 96],
            num_rounds: 0,
        }
    }
}

/// see bearssl_block.h
pub fn br_des_ct_cbcenc_init(ctx: &mut br_des_ct_cbcenc_keys, key: &[u8]) {
    ctx.num_rounds = br_des_ct_keysched(&mut ctx.skey, key);
}

/// see bearssl_block.h
pub fn br_des_ct_cbcenc_run(ctx: &br_des_ct_cbcenc_keys, iv: &mut [u8], data: &mut [u8]) {
    let mut sk_exp = [0u32; 288];
    br_des_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);
    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        for i in 0..8 {
            data[off + i] ^= iv[i];
        }
        br_des_ct_process_block(ctx.num_rounds, &sk_exp, &mut data[off..off + 8]);
        iv[..8].copy_from_slice(&data[off..off + 8]);
        off += 8;
        len -= 8;
    }
}

impl CbcEnc for br_des_ct_cbcenc_keys {
    fn run(&self, iv: &mut [u8], data: &mut [u8]) {
        br_des_ct_cbcenc_run(self, iv, data);
    }
}

/// see bearssl_block.h
pub static br_des_ct_cbcenc_vtable: br_block_cbcenc_class = br_block_cbcenc_class {
    context_size: std::mem::size_of::<br_des_ct_cbcenc_keys>(),
    block_size: 8,
    log_block_size: 3,
    init: |key| {
        let mut ctx = br_des_ct_cbcenc_keys::zeroed();
        br_des_ct_cbcenc_init(&mut ctx, key);
        Box::new(ctx)
    },
};
