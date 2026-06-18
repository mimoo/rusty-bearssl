/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! CCM record layer for TLS 1.2 (`src/ssl/ssl_rec_ccm.c`).
//!
//! Supports both the regular 16-byte tag suites (`*_AES_*_CCM`) and the 8-byte
//! tag `_CCM_8` variants. The buffer layout matches the GCM port: an 8-byte
//! explicit nonce precedes the ciphertext and the tag follows it.

use crate::aead::{
    br_ccm_aad_inject, br_ccm_check_tag, br_ccm_flip, br_ccm_get_tag, br_ccm_init, br_ccm_reset,
    br_ccm_run,
};
use crate::inner::{br_enc16be, br_enc64be};
use crate::symcipher::br_block_ctrcbc_class;

/// CCM record context (`br_sslrec_ccm_context`), used both ways.
pub struct br_sslrec_ccm_context {
    pub seq: u64,
    /// Block-cipher class + the configured key (CtrCbc), re-instantiated for
    /// each record (the C code keeps the subkeys and builds a fresh
    /// `br_ccm_context` per record).
    pub bc_impl: &'static br_block_ctrcbc_class,
    pub key: Vec<u8>,
    pub iv: [u8; 4],
    pub tag_len: usize,
}

fn gen_ccm_init(
    bc_impl: &'static br_block_ctrcbc_class,
    key: &[u8],
    iv: &[u8],
    tag_len: usize,
) -> br_sslrec_ccm_context {
    let mut cc = br_sslrec_ccm_context {
        seq: 0,
        bc_impl,
        key: key.to_vec(),
        iv: [0u8; 4],
        tag_len,
    };
    cc.iv.copy_from_slice(&iv[..4]);
    cc
}

/// see inner.h (`in_ccm_init`)
pub fn br_sslrec_in_ccm_init(
    bc_impl: &'static br_block_ctrcbc_class,
    key: &[u8],
    iv: &[u8],
    tag_len: usize,
) -> br_sslrec_ccm_context {
    gen_ccm_init(bc_impl, key, iv, tag_len)
}

/// see inner.h (`out_ccm_init`)
pub fn br_sslrec_out_ccm_init(
    bc_impl: &'static br_block_ctrcbc_class,
    key: &[u8],
    iv: &[u8],
    tag_len: usize,
) -> br_sslrec_ccm_context {
    gen_ccm_init(bc_impl, key, iv, tag_len)
}

/// see inner.h (`ccm_check_length`)
pub fn ccm_check_length(cc: &br_sslrec_ccm_context, rlen: usize) -> bool {
    let over = 8 + cc.tag_len;
    rlen >= over && rlen <= (16384 + over)
}

/// see inner.h (`ccm_max_plaintext`)
pub fn ccm_max_plaintext(cc: &br_sslrec_ccm_context, start: &mut usize, end: &mut usize) {
    *start += 8;
    let mut len = *end - *start - cc.tag_len;
    if len > 16384 {
        len = 16384;
    }
    *end = *start + len;
}

/// see inner.h (`ccm_decrypt`)
///
/// `payload` is `[8-byte explicit nonce][ciphertext][tag]`. Returns
/// `Some((offset, len))` of the recovered plaintext, or `None` on tag failure.
pub fn ccm_decrypt(
    cc: &mut br_sslrec_ccm_context,
    record_type: i32,
    version: u32,
    payload: &mut [u8],
) -> Option<(usize, usize)> {
    let len = payload.len() - (8 + cc.tag_len);

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&cc.iv);
    nonce[4..12].copy_from_slice(&payload[..8]);

    let mut header = [0u8; 13];
    br_enc64be(&mut header, cc.seq);
    cc.seq = cc.seq.wrapping_add(1);
    header[8] = record_type as u8;
    br_enc16be(&mut header[9..], version);
    br_enc16be(&mut header[11..], len as u32);

    let mut zc = br_ccm_init((cc.bc_impl.init)(&cc.key));
    br_ccm_reset(&mut zc, &nonce, header.len() as u64, len as u64, cc.tag_len);
    br_ccm_aad_inject(&mut zc, &header);
    br_ccm_flip(&mut zc);
    br_ccm_run(&mut zc, false, &mut payload[8..8 + len]);
    let tag = payload[8 + len..8 + len + cc.tag_len].to_vec();
    if br_ccm_check_tag(&mut zc, &tag) != 1 {
        return None;
    }
    Some((8, len))
}

/// see inner.h (`ccm_encrypt`)
///
/// `buf[po..po+len]` holds the plaintext; the caller leaves 13 bytes free
/// before `po` (header + explicit nonce) and `tag_len` bytes after the
/// plaintext. Returns `(offset, total_len)` of the full record within `buf`.
pub fn ccm_encrypt(
    cc: &mut br_sslrec_ccm_context,
    record_type: i32,
    version: u32,
    buf: &mut [u8],
    po: usize,
    len: usize,
) -> (usize, usize) {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&cc.iv);
    br_enc64be(&mut nonce[4..], cc.seq);

    let mut header = [0u8; 13];
    br_enc64be(&mut header, cc.seq);
    cc.seq = cc.seq.wrapping_add(1);
    header[8] = record_type as u8;
    br_enc16be(&mut header[9..], version);
    br_enc16be(&mut header[11..], len as u32);

    let mut zc = br_ccm_init((cc.bc_impl.init)(&cc.key));
    br_ccm_reset(&mut zc, &nonce, header.len() as u64, len as u64, cc.tag_len);
    br_ccm_aad_inject(&mut zc, &header);
    br_ccm_flip(&mut zc);
    br_ccm_run(&mut zc, true, &mut buf[po..po + len]);
    let mut tag = [0u8; 16];
    br_ccm_get_tag(&mut zc, &mut tag);
    buf[po + len..po + len + cc.tag_len].copy_from_slice(&tag[..cc.tag_len]);

    let rec_len = len + 8 + cc.tag_len;
    let hoff = po - 13;
    // Explicit nonce just after the 5-byte header.
    let nonce_explicit: [u8; 8] = nonce[4..12].try_into().unwrap();
    buf[hoff + 5..hoff + 13].copy_from_slice(&nonce_explicit);
    buf[hoff] = record_type as u8;
    br_enc16be(&mut buf[hoff + 1..], version);
    br_enc16be(&mut buf[hoff + 3..], rec_len as u32);
    (hoff, rec_len + 5)
}
