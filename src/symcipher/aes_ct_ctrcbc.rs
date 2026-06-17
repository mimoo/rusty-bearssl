/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! AES-ct combined CTR encryption with CBC-MAC (`src/symcipher/aes_ct_ctrcbc.c`).

use super::aes_ct::{br_aes_ct_keysched, br_aes_ct_ortho, br_aes_ct_skey_expand};
use super::aes_ct_enc::br_aes_ct_bitslice_encrypt;
use super::{br_block_ctrcbc_class, CtrCbc};
use crate::inner::{br_dec32be, br_dec32le, br_enc32be, br_enc32le, br_swap32};

/// see bearssl_block.h (`br_aes_ct_ctrcbc_keys`)
#[derive(Clone)]
pub struct br_aes_ct_ctrcbc_keys {
    pub skey: [u32; 60],
    pub num_rounds: u32,
}

impl br_aes_ct_ctrcbc_keys {
    fn zeroed() -> Self {
        br_aes_ct_ctrcbc_keys {
            skey: [0u32; 60],
            num_rounds: 0,
        }
    }
}

/// see bearssl_block.h
pub fn br_aes_ct_ctrcbc_init(ctx: &mut br_aes_ct_ctrcbc_keys, key: &[u8]) {
    ctx.num_rounds = br_aes_ct_keysched(&mut ctx.skey, key);
}

fn xorbuf(dst: &mut [u8], src: &[u8], len: usize) {
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

/// see bearssl_block.h
pub fn br_aes_ct_ctrcbc_ctr(ctx: &br_aes_ct_ctrcbc_keys, ctr: &mut [u8], data: &mut [u8]) {
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);

    /*
     * We keep the counter as four 32-bit values, with big-endian
     * convention, because that's what is expected for purposes of
     * incrementing the counter value.
     */
    let mut iv0 = br_dec32be(&ctr[0..]);
    let mut iv1 = br_dec32be(&ctr[4..]);
    let mut iv2 = br_dec32be(&ctr[8..]);
    let mut iv3 = br_dec32be(&ctr[12..]);

    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        let mut q = [0u32; 8];
        let mut tmp = [0u8; 32];

        /*
         * The bitslice implementation expects values in
         * little-endian convention, so we have to byteswap them.
         */
        q[0] = br_swap32(iv0);
        q[2] = br_swap32(iv1);
        q[4] = br_swap32(iv2);
        q[6] = br_swap32(iv3);
        iv3 = iv3.wrapping_add(1);
        let mut carry = (!(iv3 | iv3.wrapping_neg())) >> 31;
        iv2 = iv2.wrapping_add(carry);
        carry &= (!(iv2 | iv2.wrapping_neg()) >> 31).wrapping_neg();
        iv1 = iv1.wrapping_add(carry);
        carry &= (!(iv1 | iv1.wrapping_neg()) >> 31).wrapping_neg();
        iv0 = iv0.wrapping_add(carry);
        q[1] = br_swap32(iv0);
        q[3] = br_swap32(iv1);
        q[5] = br_swap32(iv2);
        q[7] = br_swap32(iv3);
        if len > 16 {
            iv3 = iv3.wrapping_add(1);
            let mut carry = (!(iv3 | iv3.wrapping_neg())) >> 31;
            iv2 = iv2.wrapping_add(carry);
            carry &= (!(iv2 | iv2.wrapping_neg()) >> 31).wrapping_neg();
            iv1 = iv1.wrapping_add(carry);
            carry &= (!(iv1 | iv1.wrapping_neg()) >> 31).wrapping_neg();
            iv0 = iv0.wrapping_add(carry);
        }

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
            break;
        }
        xorbuf(&mut data[off..], &tmp, 32);
        off += 32;
        len -= 32;
    }
    br_enc32be(&mut ctr[0..], iv0);
    br_enc32be(&mut ctr[4..], iv1);
    br_enc32be(&mut ctr[8..], iv2);
    br_enc32be(&mut ctr[12..], iv3);
}

/// see bearssl_block.h
pub fn br_aes_ct_ctrcbc_mac(ctx: &br_aes_ct_ctrcbc_keys, cbcmac: &mut [u8], data: &[u8]) {
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);

    let mut cm0 = br_dec32le(&cbcmac[0..]);
    let mut cm1 = br_dec32le(&cbcmac[4..]);
    let mut cm2 = br_dec32le(&cbcmac[8..]);
    let mut cm3 = br_dec32le(&cbcmac[12..]);
    let mut q = [0u32; 8];

    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        q[0] = cm0 ^ br_dec32le(&data[off..]);
        q[2] = cm1 ^ br_dec32le(&data[off + 4..]);
        q[4] = cm2 ^ br_dec32le(&data[off + 8..]);
        q[6] = cm3 ^ br_dec32le(&data[off + 12..]);

        br_aes_ct_ortho(&mut q);
        br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
        br_aes_ct_ortho(&mut q);

        cm0 = q[0];
        cm1 = q[2];
        cm2 = q[4];
        cm3 = q[6];
        off += 16;
        len -= 16;
    }

    br_enc32le(&mut cbcmac[0..], cm0);
    br_enc32le(&mut cbcmac[4..], cm1);
    br_enc32le(&mut cbcmac[8..], cm2);
    br_enc32le(&mut cbcmac[12..], cm3);
}

/// see bearssl_block.h
pub fn br_aes_ct_ctrcbc_encrypt(
    ctx: &br_aes_ct_ctrcbc_keys,
    ctr: &mut [u8],
    cbcmac: &mut [u8],
    data: &mut [u8],
) {
    /*
     * When encrypting, the CBC-MAC processing must be lagging by
     * one block, since it operates on the encrypted values.
     */
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);

    let mut iv0 = br_dec32be(&ctr[0..]);
    let mut iv1 = br_dec32be(&ctr[4..]);
    let mut iv2 = br_dec32be(&ctr[8..]);
    let mut iv3 = br_dec32be(&ctr[12..]);

    let mut cm0 = br_dec32le(&cbcmac[0..]);
    let mut cm1 = br_dec32le(&cbcmac[4..]);
    let mut cm2 = br_dec32le(&cbcmac[8..]);
    let mut cm3 = br_dec32le(&cbcmac[12..]);

    let mut off = 0;
    let mut len = data.len();
    let mut first_iter = true;
    while len > 0 {
        let mut q = [0u32; 8];

        q[0] = br_swap32(iv0);
        q[2] = br_swap32(iv1);
        q[4] = br_swap32(iv2);
        q[6] = br_swap32(iv3);
        iv3 = iv3.wrapping_add(1);
        let mut carry = (!(iv3 | iv3.wrapping_neg())) >> 31;
        iv2 = iv2.wrapping_add(carry);
        carry &= (!(iv2 | iv2.wrapping_neg()) >> 31).wrapping_neg();
        iv1 = iv1.wrapping_add(carry);
        carry &= (!(iv1 | iv1.wrapping_neg()) >> 31).wrapping_neg();
        iv0 = iv0.wrapping_add(carry);

        /*
         * The odd values are used for CBC-MAC.
         */
        q[1] = cm0;
        q[3] = cm1;
        q[5] = cm2;
        q[7] = cm3;

        br_aes_ct_ortho(&mut q);
        br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
        br_aes_ct_ortho(&mut q);

        q[0] ^= br_dec32le(&data[off..]);
        q[2] ^= br_dec32le(&data[off + 4..]);
        q[4] ^= br_dec32le(&data[off + 8..]);
        q[6] ^= br_dec32le(&data[off + 12..]);
        br_enc32le(&mut data[off..], q[0]);
        br_enc32le(&mut data[off + 4..], q[2]);
        br_enc32le(&mut data[off + 8..], q[4]);
        br_enc32le(&mut data[off + 12..], q[6]);

        off += 16;
        len -= 16;

        if first_iter {
            first_iter = false;
            cm0 ^= q[0];
            cm1 ^= q[2];
            cm2 ^= q[4];
            cm3 ^= q[6];
        } else {
            cm0 = q[0] ^ q[1];
            cm1 = q[2] ^ q[3];
            cm2 = q[4] ^ q[5];
            cm3 = q[6] ^ q[7];
        }

        if len == 0 {
            q[0] = cm0;
            q[2] = cm1;
            q[4] = cm2;
            q[6] = cm3;
            br_aes_ct_ortho(&mut q);
            br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
            br_aes_ct_ortho(&mut q);
            cm0 = q[0];
            cm1 = q[2];
            cm2 = q[4];
            cm3 = q[6];
            break;
        }
    }

    br_enc32be(&mut ctr[0..], iv0);
    br_enc32be(&mut ctr[4..], iv1);
    br_enc32be(&mut ctr[8..], iv2);
    br_enc32be(&mut ctr[12..], iv3);
    br_enc32le(&mut cbcmac[0..], cm0);
    br_enc32le(&mut cbcmac[4..], cm1);
    br_enc32le(&mut cbcmac[8..], cm2);
    br_enc32le(&mut cbcmac[12..], cm3);
}

/// see bearssl_block.h
pub fn br_aes_ct_ctrcbc_decrypt(
    ctx: &br_aes_ct_ctrcbc_keys,
    ctr: &mut [u8],
    cbcmac: &mut [u8],
    data: &mut [u8],
) {
    let mut sk_exp = [0u32; 120];
    br_aes_ct_skey_expand(&mut sk_exp, ctx.num_rounds, &ctx.skey);

    let mut iv0 = br_dec32be(&ctr[0..]);
    let mut iv1 = br_dec32be(&ctr[4..]);
    let mut iv2 = br_dec32be(&ctr[8..]);
    let mut iv3 = br_dec32be(&ctr[12..]);

    let mut cm0 = br_dec32le(&cbcmac[0..]);
    let mut cm1 = br_dec32le(&cbcmac[4..]);
    let mut cm2 = br_dec32le(&cbcmac[8..]);
    let mut cm3 = br_dec32le(&cbcmac[12..]);

    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        let mut q = [0u32; 8];
        let mut tmp = [0u8; 16];

        q[0] = br_swap32(iv0);
        q[2] = br_swap32(iv1);
        q[4] = br_swap32(iv2);
        q[6] = br_swap32(iv3);
        iv3 = iv3.wrapping_add(1);
        let mut carry = (!(iv3 | iv3.wrapping_neg())) >> 31;
        iv2 = iv2.wrapping_add(carry);
        carry &= (!(iv2 | iv2.wrapping_neg()) >> 31).wrapping_neg();
        iv1 = iv1.wrapping_add(carry);
        carry &= (!(iv1 | iv1.wrapping_neg()) >> 31).wrapping_neg();
        iv0 = iv0.wrapping_add(carry);

        /*
         * The odd values are used for CBC-MAC.
         */
        q[1] = cm0 ^ br_dec32le(&data[off..]);
        q[3] = cm1 ^ br_dec32le(&data[off + 4..]);
        q[5] = cm2 ^ br_dec32le(&data[off + 8..]);
        q[7] = cm3 ^ br_dec32le(&data[off + 12..]);

        br_aes_ct_ortho(&mut q);
        br_aes_ct_bitslice_encrypt(ctx.num_rounds, &sk_exp, &mut q);
        br_aes_ct_ortho(&mut q);

        br_enc32le(&mut tmp[0..], q[0]);
        br_enc32le(&mut tmp[4..], q[2]);
        br_enc32le(&mut tmp[8..], q[4]);
        br_enc32le(&mut tmp[12..], q[6]);
        xorbuf(&mut data[off..], &tmp, 16);
        cm0 = q[1];
        cm1 = q[3];
        cm2 = q[5];
        cm3 = q[7];
        off += 16;
        len -= 16;
    }

    br_enc32be(&mut ctr[0..], iv0);
    br_enc32be(&mut ctr[4..], iv1);
    br_enc32be(&mut ctr[8..], iv2);
    br_enc32be(&mut ctr[12..], iv3);
    br_enc32le(&mut cbcmac[0..], cm0);
    br_enc32le(&mut cbcmac[4..], cm1);
    br_enc32le(&mut cbcmac[8..], cm2);
    br_enc32le(&mut cbcmac[12..], cm3);
}

impl CtrCbc for br_aes_ct_ctrcbc_keys {
    fn encrypt(&self, ctr: &mut [u8], cbcmac: &mut [u8], data: &mut [u8]) {
        br_aes_ct_ctrcbc_encrypt(self, ctr, cbcmac, data);
    }
    fn decrypt(&self, ctr: &mut [u8], cbcmac: &mut [u8], data: &mut [u8]) {
        br_aes_ct_ctrcbc_decrypt(self, ctr, cbcmac, data);
    }
    fn ctr(&self, ctr: &mut [u8], data: &mut [u8]) {
        br_aes_ct_ctrcbc_ctr(self, ctr, data);
    }
    fn mac(&self, cbcmac: &mut [u8], data: &[u8]) {
        br_aes_ct_ctrcbc_mac(self, cbcmac, data);
    }
}

/// see bearssl_block.h
pub static br_aes_ct_ctrcbc_vtable: br_block_ctrcbc_class = br_block_ctrcbc_class {
    context_size: std::mem::size_of::<br_aes_ct_ctrcbc_keys>(),
    block_size: 16,
    log_block_size: 4,
    init: |key| {
        let mut ctx = br_aes_ct_ctrcbc_keys::zeroed();
        br_aes_ct_ctrcbc_init(&mut ctx, key);
        Box::new(ctx)
    },
};
