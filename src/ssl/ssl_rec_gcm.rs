/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! GCM record layer for TLS 1.2 (`src/ssl/ssl_rec_gcm.c`).
//!
//! Porting note: the C code does in-place crypto using negative pointer
//! offsets relative to the plaintext (the engine reserves a 13-byte record
//! header + 8-byte explicit nonce before the plaintext, and 16 bytes for the
//! tag after it). Here the buffer is passed as a slice with an explicit
//! plaintext offset, so the same byte layout is preserved without raw pointers.

use crate::hash::br_ghash;
use crate::inner::{br_enc16be, br_enc64be};
use crate::symcipher::{br_block_ctr_class, Ctr};

/// Context for processing records with GCM (encrypt or decrypt).
pub struct br_sslrec_gcm_context {
    pub seq: u64,
    pub bc: Box<dyn Ctr>,
    pub gh: br_ghash,
    pub iv: [u8; 4],
    pub h: [u8; 16],
}

fn gen_gcm_init(
    bc_impl: &br_block_ctr_class,
    key: &[u8],
    gh_impl: br_ghash,
    iv: &[u8],
) -> br_sslrec_gcm_context {
    let bc = (bc_impl.init)(key);
    let mut cc = br_sslrec_gcm_context {
        seq: 0,
        bc,
        gh: gh_impl,
        iv: [0u8; 4],
        h: [0u8; 16],
    };
    cc.iv.copy_from_slice(&iv[..4]);
    // h = E_K(0^128) via CTR with zero IV and counter 0.
    let tmp = [0u8; 12];
    cc.bc.run(&tmp, 0, &mut cc.h);
    cc
}

/// see bearssl_ssl.h (decryption-side init)
pub fn br_sslrec_in_gcm_init(
    bc_impl: &br_block_ctr_class,
    key: &[u8],
    gh_impl: br_ghash,
    iv: &[u8],
) -> br_sslrec_gcm_context {
    gen_gcm_init(bc_impl, key, gh_impl, iv)
}

/// see bearssl_ssl.h (encryption-side init)
pub fn br_sslrec_out_gcm_init(
    bc_impl: &br_block_ctr_class,
    key: &[u8],
    gh_impl: br_ghash,
    iv: &[u8],
) -> br_sslrec_gcm_context {
    gen_gcm_init(bc_impl, key, gh_impl, iv)
}

/// see bearssl_ssl.h
pub fn gcm_check_length(_cc: &br_sslrec_gcm_context, rlen: usize) -> bool {
    rlen >= 24 && rlen <= (16384 + 24)
}

/// Compute the authentication tag (still to be CTR-encrypted) over the
/// 13-byte header, the ciphertext `data`, and the length footer.
fn do_tag(cc: &mut br_sslrec_gcm_context, record_type: i32, version: u32, data: &[u8], tag: &mut [u8]) {
    let len = data.len();
    let mut header = [0u8; 13];
    let mut footer = [0u8; 16];
    br_enc64be(&mut header, cc.seq);
    cc.seq += 1;
    header[8] = record_type as u8;
    br_enc16be(&mut header[9..], version);
    br_enc16be(&mut header[11..], len as u32);
    br_enc64be(&mut footer, (header.len() as u64) << 3);
    br_enc64be(&mut footer[8..], (len as u64) << 3);
    for b in tag[..16].iter_mut() {
        *b = 0;
    }
    (cc.gh)(tag, &cc.h, &header);
    (cc.gh)(tag, &cc.h, data);
    (cc.gh)(tag, &cc.h, &footer);
}

/// CTR-encrypt `data` (counter starts at 2) and the tag block `xortag`
/// (counter 1), using IV = fixed_iv(4) || nonce(8).
fn do_ctr(cc: &mut br_sslrec_gcm_context, nonce: &[u8], data: &mut [u8], xortag: &mut [u8]) {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(&cc.iv);
    iv[4..12].copy_from_slice(&nonce[..8]);
    cc.bc.run(&iv, 2, data);
    cc.bc.run(&iv, 1, xortag);
}

/// see bearssl_ssl.h
///
/// `payload` is the record payload: `[8-byte explicit nonce][ciphertext][16-byte tag]`.
/// On success returns `Some((offset, len))` of the recovered plaintext within
/// `payload`; on MAC failure returns `None`.
pub fn gcm_decrypt(
    cc: &mut br_sslrec_gcm_context,
    record_type: i32,
    version: u32,
    payload: &mut [u8],
) -> Option<(usize, usize)> {
    let total = payload.len();
    let len = total - 24;
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&payload[..8]);

    let mut tag = [0u8; 16];
    do_tag(cc, record_type, version, &payload[8..8 + len], &mut tag);
    do_ctr(cc, &nonce, &mut payload[8..8 + len], &mut tag);

    let mut bad = 0u8;
    for u in 0..16 {
        bad |= tag[u] ^ payload[8 + len + u];
    }
    if bad != 0 {
        return None;
    }
    Some((8, len))
}

/// see bearssl_ssl.h
///
/// Adjust the plaintext window for the GCM overhead (8-byte nonce prefix +
/// 16-byte tag), capped at the 16384-byte record limit.
pub fn gcm_max_plaintext(_cc: &br_sslrec_gcm_context, start: &mut usize, end: &mut usize) {
    *start += 8;
    let mut len = *end - *start - 16;
    if len > 16384 {
        len = 16384;
    }
    *end = *start + len;
}

/// see bearssl_ssl.h
///
/// Encrypt the plaintext in place. `buf[po..po+len]` holds the plaintext; the
/// caller must leave 13 bytes free before `po` (record header + explicit nonce)
/// and 16 bytes after the plaintext (tag). Returns `(offset, total_len)` of the
/// complete record (including its 5-byte header) within `buf`.
pub fn gcm_encrypt(
    cc: &mut br_sslrec_gcm_context,
    record_type: i32,
    version: u32,
    buf: &mut [u8],
    po: usize,
    len: usize,
) -> (usize, usize) {
    let mut tmp = [0u8; 16];
    // Explicit nonce = sequence number, written just before the plaintext.
    br_enc64be(&mut buf[po - 8..po], cc.seq);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[po - 8..po]);

    do_ctr(cc, &nonce, &mut buf[po..po + len], &mut tmp);
    // do_tag does seq++ ; compute it over the ciphertext, write into buf after.
    let mut tag = [0u8; 16];
    do_tag(cc, record_type, version, &buf[po..po + len], &mut tag);
    for u in 0..16 {
        buf[po + len + u] = tag[u] ^ tmp[u];
    }
    let rec_len = len + 24;
    let hoff = po - 13;
    buf[hoff] = record_type as u8;
    br_enc16be(&mut buf[hoff + 1..], version);
    br_enc16be(&mut buf[hoff + 3..], rec_len as u32);
    (hoff, rec_len + 5)
}
