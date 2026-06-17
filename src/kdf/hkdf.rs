/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! HKDF (`src/kdf/hkdf.c`), the HMAC-based KDF from RFC 5869.

use crate::hash::{br_digest_size, br_hash_class};
use crate::mac::{
    br_hmac_context, br_hmac_get_digest, br_hmac_init, br_hmac_key_context, br_hmac_key_init,
    br_hmac_out, br_hmac_size, br_hmac_update,
};

/// HKDF context.
///
/// Porting note: the C version overlays `hmac_ctx` (extract phase) and
/// `prk_ctx` (expand phase) in a `union u`, since they are live in disjoint
/// phases. We keep them as separate fields; behaviour is identical.
pub struct br_hkdf_context {
    pub hmac_ctx: Option<br_hmac_context>,
    pub prk_ctx: Option<br_hmac_key_context>,
    pub buf: [u8; 64],
    pub ptr: usize,
    pub dig_len: usize,
    pub chunk_num: u32,
}

/// see bearssl_kdf.h
///
/// `salt = None` selects `BR_HKDF_NO_SALT` (an all-zero salt of digest length).
pub fn br_hkdf_init(
    hc: &mut br_hkdf_context,
    digest_vtable: &'static br_hash_class,
    salt: &[u8],
    salt_len: usize,
) {
    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, digest_vtable, salt, salt_len);
    let hmac_ctx = br_hmac_context::new(&kc, 0);
    hc.dig_len = br_hmac_size(&hmac_ctx);
    hc.hmac_ctx = Some(hmac_ctx);
    hc.prk_ctx = None;
    hc.ptr = 0;
    hc.chunk_num = 0;
}

/// `br_hkdf_init` with `BR_HKDF_NO_SALT`: an all-zero salt of digest length.
pub fn br_hkdf_init_no_salt(hc: &mut br_hkdf_context, digest_vtable: &'static br_hash_class) {
    let tmp = [0u8; 64];
    let salt_len = br_digest_size(digest_vtable);
    br_hkdf_init(hc, digest_vtable, &tmp[..salt_len], salt_len);
}

/// see bearssl_kdf.h
pub fn br_hkdf_inject(hc: &mut br_hkdf_context, ikm: &[u8], ikm_len: usize) {
    br_hmac_update(hc.hmac_ctx.as_mut().unwrap(), ikm, ikm_len);
}

/// see bearssl_kdf.h
pub fn br_hkdf_flip(hc: &mut br_hkdf_context) {
    let mut tmp = [0u8; 64];
    let hmac_ctx = hc.hmac_ctx.as_ref().unwrap();
    br_hmac_out(hmac_ctx, &mut tmp);
    let dig = br_hmac_get_digest(hmac_ctx);
    let mut prk = br_hmac_key_context::default();
    br_hmac_key_init(&mut prk, dig, &tmp, hc.dig_len);
    hc.prk_ctx = Some(prk);
    hc.hmac_ctx = None;
    hc.ptr = hc.dig_len;
    hc.chunk_num = 0;
}

/// see bearssl_kdf.h
pub fn br_hkdf_produce(
    hc: &mut br_hkdf_context,
    info: &[u8],
    info_len: usize,
    out: &mut [u8],
    out_len: usize,
) -> usize {
    let mut tlen = 0usize;
    let mut out_off = 0usize;
    let mut out_len = out_len;
    while out_len > 0 {
        if hc.ptr == hc.dig_len {
            hc.chunk_num += 1;
            if hc.chunk_num == 256 {
                return tlen;
            }
            let x = hc.chunk_num as u8;
            let mut hmac_ctx = br_hmac_context::new(hc.prk_ctx.as_ref().unwrap(), 0);
            if x != 1 {
                let buf = hc.buf;
                br_hmac_update(&mut hmac_ctx, &buf, hc.dig_len);
            }
            br_hmac_update(&mut hmac_ctx, info, info_len);
            br_hmac_update(&mut hmac_ctx, &[x], 1);
            br_hmac_out(&hmac_ctx, &mut hc.buf);
            hc.ptr = 0;
        }
        let mut clen = hc.dig_len - hc.ptr;
        if clen > out_len {
            clen = out_len;
        }
        out[out_off..out_off + clen].copy_from_slice(&hc.buf[hc.ptr..hc.ptr + clen]);
        out_off += clen;
        out_len -= clen;
        hc.ptr += clen;
        tlen += clen;
    }
    tlen
}

impl Default for br_hkdf_context {
    fn default() -> Self {
        br_hkdf_context {
            hmac_ctx: None,
            prk_ctx: None,
            buf: [0u8; 64],
            ptr: 0,
            dig_len: 0,
            chunk_num: 0,
        }
    }
}
