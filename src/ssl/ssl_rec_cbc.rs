/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! CBC record layer (`src/ssl/ssl_rec_cbc.c`): MAC-then-encrypt with a
//! constant-time decrypt path (padding + HMAC verification using
//! `br_hmac_outCT`).
//!
//! Porting note: the C code does in-place crypto with negative pointer offsets
//! relative to the plaintext. As with the GCM port, the buffer is passed as a
//! slice with an explicit plaintext offset `po`, and the recovered/produced
//! record window is returned as `(offset, len)`.

use crate::inner::{br_enc16be, br_enc64be, EQ, EQ0, GE, LE, LT, MUX};
use crate::mac::{
    br_hmac_context, br_hmac_key_context, br_hmac_key_init, br_hmac_out, br_hmac_outCT,
    br_hmac_update,
};
use crate::symcipher::{br_block_cbcdec_class, br_block_cbcenc_class, CbcDec, CbcEnc};

use super::ssl_engine::BR_SSL_APPLICATION_DATA;

/// Incoming (decrypt) CBC record context (`br_sslrec_in_cbc_context`).
pub struct br_sslrec_in_cbc_context {
    pub seq: u64,
    pub bc: Box<dyn CbcDec>,
    pub block_size: usize,
    pub mac: br_hmac_key_context,
    pub mac_len: usize,
    pub iv: [u8; 16],
    pub explicit_iv: bool,
}

/// Outgoing (encrypt) CBC record context (`br_sslrec_out_cbc_context`).
pub struct br_sslrec_out_cbc_context {
    pub seq: u64,
    pub bc: Box<dyn CbcEnc>,
    pub block_size: usize,
    pub mac: br_hmac_key_context,
    pub mac_len: usize,
    pub iv: [u8; 16],
    pub explicit_iv: bool,
}

// ---- init -------------------------------------------------------------------

/// see inner.h (`in_cbc_init`)
pub fn br_sslrec_in_cbc_init(
    bc_impl: &br_block_cbcdec_class,
    bc_key: &[u8],
    dig_impl: &'static crate::hash::br_hash_class,
    mac_key: &[u8],
    mac_out_len: usize,
    iv: Option<&[u8]>,
) -> br_sslrec_in_cbc_context {
    let block_size = bc_impl.block_size as usize;
    let mut mac = br_hmac_key_context::default();
    br_hmac_key_init(&mut mac, dig_impl, mac_key, mac_key.len());
    let mut cc = br_sslrec_in_cbc_context {
        seq: 0,
        bc: (bc_impl.init)(bc_key),
        block_size,
        mac,
        mac_len: mac_out_len,
        iv: [0u8; 16],
        explicit_iv: false,
    };
    match iv {
        None => {
            cc.explicit_iv = true;
        }
        Some(iv) => {
            cc.iv[..block_size].copy_from_slice(&iv[..block_size]);
            cc.explicit_iv = false;
        }
    }
    cc
}

/// see inner.h (`out_cbc_init`)
pub fn br_sslrec_out_cbc_init(
    bc_impl: &br_block_cbcenc_class,
    bc_key: &[u8],
    dig_impl: &'static crate::hash::br_hash_class,
    mac_key: &[u8],
    mac_out_len: usize,
    iv: Option<&[u8]>,
) -> br_sslrec_out_cbc_context {
    let block_size = bc_impl.block_size as usize;
    let mut mac = br_hmac_key_context::default();
    br_hmac_key_init(&mut mac, dig_impl, mac_key, mac_key.len());
    let mut cc = br_sslrec_out_cbc_context {
        seq: 0,
        bc: (bc_impl.init)(bc_key),
        block_size,
        mac,
        mac_len: mac_out_len,
        iv: [0u8; 16],
        explicit_iv: false,
    };
    match iv {
        None => {
            cc.explicit_iv = true;
        }
        Some(iv) => {
            cc.iv[..block_size].copy_from_slice(&iv[..block_size]);
            cc.explicit_iv = false;
        }
    }
    cc
}

// ---- check_length / max_plaintext -------------------------------------------

/// see inner.h (`cbc_check_length`)
pub fn cbc_check_length(cc: &br_sslrec_in_cbc_context, rlen: usize) -> bool {
    let blen = cc.block_size;
    let mut min_len = (blen + cc.mac_len) & !(blen - 1);
    let mut max_len = (16384 + 256 + cc.mac_len) & !(blen - 1);
    if cc.explicit_iv {
        min_len += blen;
        max_len += blen;
    }
    min_len <= rlen && rlen <= max_len && (rlen & (blen - 1)) == 0
}

/// see inner.h (`cbc_max_plaintext`)
pub fn cbc_max_plaintext(cc: &br_sslrec_out_cbc_context, start: &mut usize, end: &mut usize) {
    let blen = cc.block_size;
    if cc.explicit_iv {
        *start += blen;
    } else {
        *start += 4 + ((cc.mac_len + blen + 1) & !(blen - 1));
    }
    let mut len = (*end - *start) & !(blen - 1);
    len -= 1 + cc.mac_len;
    if len > 16384 {
        len = 16384;
    }
    *end = *start + len;
}

// ---- decrypt ----------------------------------------------------------------

/// Rotate `buf[..len]` left by `num` bytes iff `ctl == 1` (constant-time).
/// `num` MUST be lower than `len`; `len` MUST be <= 64 (`cond_rotate`).
fn cond_rotate(ctl: u32, buf: &mut [u8], len: usize, num: usize) {
    let mut tmp = [0u8; 64];
    let mut v = num;
    for u in 0..len {
        tmp[u] = MUX(ctl, buf[v] as u32, buf[u] as u32) as u8;
        v += 1;
        if v == len {
            v = 0;
        }
    }
    buf[..len].copy_from_slice(&tmp[..len]);
}

/// see inner.h (`cbc_decrypt`)
///
/// `payload` is the encrypted record body. On success returns `Some((offset,
/// len))` of the recovered plaintext within `payload`; `None` on MAC/padding
/// failure.
pub fn cbc_decrypt(
    cc: &mut br_sslrec_in_cbc_context,
    record_type: i32,
    version: u32,
    payload: &mut [u8],
) -> Option<(usize, usize)> {
    let blen = cc.block_size;
    let mut len = payload.len() as u32;

    // Decrypt the whole body (including any explicit IV block).
    {
        let mut iv = cc.iv;
        cc.bc.run(&mut iv[..blen], payload);
        cc.iv = iv;
    }
    let mut base = 0usize; // offset within payload of the post-IV plaintext+MAC
    if cc.explicit_iv {
        base += blen;
        len -= blen as u32;
    }
    let buf = &mut payload[base..];

    // Public bounds on plaintext + MAC.
    let mac_len = cc.mac_len as u32;
    let mut min_len = if mac_len + 256 < len {
        len - 256
    } else {
        mac_len
    };
    let max_len = len - 1;

    // Padding length from the last byte.
    let pad_len = buf[max_len as usize] as u32;
    let mut good = LE(pad_len, max_len - min_len);
    len = MUX(good, max_len - pad_len, min_len);

    // All padding bytes must equal pad_len.
    for u in min_len..max_len {
        good &= LT(u, len) | EQ(buf[u as usize] as u32, pad_len);
    }

    // Extract the (rotated) MAC value in one pass.
    let len_withmac = len;
    let len_nomac = len_withmac - mac_len;
    min_len -= mac_len;
    let mut rot_count = 0u32;
    let mut tmp1 = [0u8; 64];
    let mut v = 0usize;
    for u in min_len..max_len {
        tmp1[v] |= MUX(
            GE(u, len_nomac) & LT(u, len_withmac),
            buf[u as usize] as u32,
            0x00,
        ) as u8;
        rot_count = MUX(EQ(u, len_nomac), v as u32, rot_count);
        v += 1;
        if v == cc.mac_len {
            v = 0;
        }
    }
    let max_len_nomac = max_len - mac_len;

    // Rotate the MAC back into place (constant-time, n*log n).
    for i in (0..=5i32).rev() {
        let rc = 1u32 << i;
        cond_rotate(rot_count >> i, &mut tmp1, cc.mac_len, rc as usize);
        rot_count &= !rc;
    }

    // Recompute the HMAC over seq || header(5) || payload.
    let mut tmp2 = [0u8; 64];
    let mut hdr = [0u8; 13];
    br_enc64be(&mut hdr, cc.seq);
    cc.seq = cc.seq.wrapping_add(1);
    hdr[8] = record_type as u8;
    br_enc16be(&mut hdr[9..], version);
    br_enc16be(&mut hdr[11..], len_nomac);
    let mut hc = br_hmac_context::new(&cc.mac, cc.mac_len);
    br_hmac_update(&mut hc, &hdr, 13);
    br_hmac_outCT(
        &hc,
        buf,
        len_nomac as usize,
        min_len as usize,
        max_len_nomac as usize,
        &mut tmp2,
    );

    // Compare the extracted and recomputed MAC values.
    for u in 0..cc.mac_len {
        good &= EQ0((tmp1[u] ^ tmp2[u]) as i32);
    }

    // Final plaintext-length sanity check.
    good &= LE(len_nomac, 16384);

    if good == 0 {
        return None;
    }
    Some((base, len_nomac as usize))
}

// ---- encrypt ----------------------------------------------------------------

/// see inner.h (`cbc_encrypt`)
///
/// `buf[po..po+len]` holds the plaintext. The caller leaves room before `po`
/// (header + optional explicit-IV block / split fragment) and after the
/// plaintext (MAC + padding). Returns `(offset, total_len)` of the complete
/// record (including its 5-byte header) within `buf`.
pub fn cbc_encrypt(
    cc: &mut br_sslrec_out_cbc_context,
    record_type: i32,
    version: u32,
    buf: &mut [u8],
    po: usize,
    len: usize,
) -> (usize, usize) {
    let blen = cc.block_size;
    let mac_len = cc.mac_len;

    // Determine the buffer start (`rbuf`) and the plaintext start (`pstart`),
    // mirroring the negative-offset pointer arithmetic of the C code.
    let mut pstart = po;
    let mut plen = len;
    let rbuf: usize;

    if cc.explicit_iv {
        // Explicit IV: an extra leading block, derived via HMAC over seq, placed
        // just before the plaintext. The MAC and padding still cover only the
        // plaintext; the IV block is folded into the encryption span at the end.
        let mut tmp = [0u8; 13];
        br_enc64be(&mut tmp, cc.seq);
        let mut hc = br_hmac_context::new(&cc.mac, blen);
        br_hmac_update(&mut hc, &tmp, 8);
        let mut ivblock = [0u8; 16];
        br_hmac_out(&hc, &mut ivblock);
        buf[po - blen..po].copy_from_slice(&ivblock[..blen]);
        rbuf = po - blen - 5;
    } else if len > 1 && record_type == BR_SSL_APPLICATION_DATA as i32 {
        // TLS 1.0 1/n-1 split: emit a one-byte record first, immediately
        // preceding this one in RAM, then continue with the remaining bytes.
        let split_start = po - 4 - ((mac_len + blen + 1) & !(blen - 1));
        buf[split_start] = buf[po];
        let (rb, _) = cbc_encrypt(cc, record_type, version, buf, split_start, 1);
        rbuf = rb;
        pstart = po + 1;
        plen = len - 1;
    } else {
        rbuf = po - 5;
    }

    // Compute the MAC over seq || header(5) || plaintext, appended after it.
    let mut tmp = [0u8; 13];
    br_enc64be(&mut tmp, cc.seq);
    cc.seq = cc.seq.wrapping_add(1);
    tmp[8] = record_type as u8;
    br_enc16be(&mut tmp[9..], version);
    br_enc16be(&mut tmp[11..], plen as u32);
    let mut hc = br_hmac_context::new(&cc.mac, mac_len);
    br_hmac_update(&mut hc, &tmp, 13);
    br_hmac_update(&mut hc, &buf[pstart..pstart + plen], plen);
    let mut macbuf = [0u8; 64];
    br_hmac_out(&hc, &mut macbuf);
    buf[pstart + plen..pstart + plen + mac_len].copy_from_slice(&macbuf[..mac_len]);
    let mut total = plen + mac_len;

    // Padding.
    let pad = blen - (total & (blen - 1));
    for b in buf[pstart + total..pstart + total + pad].iter_mut() {
        *b = (pad - 1) as u8;
    }
    total += pad;

    // Account for the explicit-IV block (already in place).
    let (enc_start, enc_len) = if cc.explicit_iv {
        (pstart - blen, total + blen)
    } else {
        (pstart, total)
    };

    // Encrypt the whole thing (explicit-IV block included).
    {
        let mut iv = cc.iv;
        cc.bc.run(&mut iv[..blen], &mut buf[enc_start..enc_start + enc_len]);
        cc.iv = iv;
    }

    // Header.
    buf[enc_start - 5] = record_type as u8;
    br_enc16be(&mut buf[enc_start - 4..], version);
    br_enc16be(&mut buf[enc_start - 2..], enc_len as u32);

    let end = enc_start + enc_len;
    (rbuf, end - rbuf)
}
