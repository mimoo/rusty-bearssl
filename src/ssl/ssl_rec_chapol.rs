/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ChaCha20+Poly1305 record layer for TLS 1.2 (`src/ssl/ssl_rec_chapol.c`).
//!
//! The only per-record overhead is the 16-byte Poly1305 tag (plus the 5-byte
//! record header on output). The per-record nonce is the fixed 12-byte IV with
//! the 64-bit sequence number XORed into its low 8 bytes.

use crate::inner::{br_enc16be, br_enc64be};
use crate::symcipher::br_chacha20_run;

/// A Poly1305-with-ChaCha20 AEAD run function (`br_poly1305_run`).
pub type br_poly1305_run =
    fn(key: &[u8], iv: &[u8], data: &mut [u8], aad: &[u8], tag: &mut [u8], ichacha: br_chacha20_run, encrypt: i32);

/// Context for processing records with ChaCha20+Poly1305 (encrypt or decrypt).
pub struct br_sslrec_chapol_context {
    pub seq: u64,
    pub ichacha: br_chacha20_run,
    pub ipoly: br_poly1305_run,
    pub key: [u8; 32],
    pub iv: [u8; 12],
}

fn gen_chapol_init(
    ichacha: br_chacha20_run,
    ipoly: br_poly1305_run,
    key: &[u8],
    iv: &[u8],
) -> br_sslrec_chapol_context {
    let mut cc = br_sslrec_chapol_context {
        seq: 0,
        ichacha,
        ipoly,
        key: [0u8; 32],
        iv: [0u8; 12],
    };
    cc.key.copy_from_slice(&key[..32]);
    cc.iv.copy_from_slice(&iv[..12]);
    cc
}

/// see bearssl_ssl.h (decryption-side init)
pub fn br_sslrec_in_chapol_init(
    ichacha: br_chacha20_run,
    ipoly: br_poly1305_run,
    key: &[u8],
    iv: &[u8],
) -> br_sslrec_chapol_context {
    gen_chapol_init(ichacha, ipoly, key, iv)
}

/// see bearssl_ssl.h (encryption-side init)
pub fn br_sslrec_out_chapol_init(
    ichacha: br_chacha20_run,
    ipoly: br_poly1305_run,
    key: &[u8],
    iv: &[u8],
) -> br_sslrec_chapol_context {
    gen_chapol_init(ichacha, ipoly, key, iv)
}

fn gen_chapol_process(
    cc: &mut br_sslrec_chapol_context,
    record_type: i32,
    version: u32,
    data: &mut [u8],
    tag: &mut [u8],
    encrypt: i32,
) {
    let len = data.len();
    let mut header = [0u8; 13];
    let mut nonce = [0u8; 12];
    let mut seq = cc.seq;
    cc.seq += 1;
    br_enc64be(&mut header, seq);
    header[8] = record_type as u8;
    br_enc16be(&mut header[9..], version);
    br_enc16be(&mut header[11..], len as u32);
    nonce.copy_from_slice(&cc.iv);
    for u in 0..8 {
        nonce[11 - u] ^= seq as u8;
        seq >>= 8;
    }
    (cc.ipoly)(&cc.key, &nonce, data, &header, tag, cc.ichacha, encrypt);
}

/// see bearssl_ssl.h
pub fn chapol_check_length(_cc: &br_sslrec_chapol_context, rlen: usize) -> bool {
    rlen >= 16 && rlen <= (16384 + 16)
}

/// see bearssl_ssl.h
///
/// `payload` is `[ciphertext][16-byte tag]`. Returns `Some((0, len))` of the
/// recovered plaintext on success, `None` on MAC failure.
pub fn chapol_decrypt(
    cc: &mut br_sslrec_chapol_context,
    record_type: i32,
    version: u32,
    payload: &mut [u8],
) -> Option<(usize, usize)> {
    let len = payload.len() - 16;
    let mut tag = [0u8; 16];
    {
        let (data, rectag) = payload.split_at_mut(len);
        gen_chapol_process(cc, record_type, version, data, &mut tag, 0);
        let mut bad = 0u8;
        for u in 0..16 {
            bad |= tag[u] ^ rectag[u];
        }
        if bad != 0 {
            return None;
        }
    }
    Some((0, len))
}

/// see bearssl_ssl.h
pub fn chapol_max_plaintext(_cc: &br_sslrec_chapol_context, start: &mut usize, end: &mut usize) {
    let mut len = *end - *start - 16;
    if len > 16384 {
        len = 16384;
    }
    *end = *start + len;
}

/// see bearssl_ssl.h
///
/// Encrypt `buf[po..po+len]` in place; the caller leaves 5 bytes free before
/// `po` (record header) and 16 bytes after the plaintext (tag). Returns
/// `(offset, total_len)` of the complete record (including 5-byte header).
pub fn chapol_encrypt(
    cc: &mut br_sslrec_chapol_context,
    record_type: i32,
    version: u32,
    buf: &mut [u8],
    po: usize,
    len: usize,
) -> (usize, usize) {
    {
        let (data, tag) = buf[po..po + len + 16].split_at_mut(len);
        gen_chapol_process(cc, record_type, version, data, tag, 1);
    }
    let hoff = po - 5;
    buf[hoff] = record_type as u8;
    br_enc16be(&mut buf[hoff + 1..], version);
    br_enc16be(&mut buf[hoff + 3..], (len + 16) as u32);
    (hoff, len + 21)
}
