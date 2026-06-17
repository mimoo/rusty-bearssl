/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_pkcs1_sig_unpad` (mirrors `src/rsa/rsa_pkcs1_sig_unpad.c`).

/// see bearssl_rsa.h
///
/// Verify PKCS#1 v1.5 padding of `sig` and extract the hash value into
/// `hash_out`. Returns 1 on success, 0 on error. Need not be constant-time.
pub fn br_rsa_pkcs1_sig_unpad(
    sig: &[u8],
    hash_oid: Option<&[u8]>,
    hash_len: usize,
    hash_out: &mut [u8],
) -> u32 {
    const PAD1: [u8; 10] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let mut pad2 = [0u8; 43];
    let sig_len = sig.len();

    if sig_len < 11 {
        return 0;
    }

    // Check the "00 01 FF .. FF 00" with at least eight 0xFF bytes.
    if sig[..PAD1.len()] != PAD1 {
        return 0;
    }
    let mut u = PAD1.len();
    while u < sig_len {
        if sig[u] != 0xFF {
            break;
        }
        u += 1;
    }

    // Remaining length is sig_len - u bytes (including the 00 just after the
    // last FF).
    match hash_oid {
        None => {
            if sig_len - u != hash_len + 1 || sig[u] != 0x00 {
                return 0;
            }
        }
        Some(hash_oid) => {
            let x3 = hash_oid[0] as usize;
            let mut pad_len = x3 + 9;
            for b in pad2[..pad_len].iter_mut() {
                *b = 0;
            }
            let zlen = sig_len - u - hash_len;
            let x2;
            if zlen == pad_len {
                x2 = x3 + 2;
            } else if zlen == pad_len + 2 {
                x2 = x3 + 4;
                pad_len = zlen;
                pad2[pad_len - 4] = 0x05;
            } else {
                return 0;
            }
            pad2[1] = 0x30;
            pad2[2] = (x2 + hash_len + 4) as u8;
            pad2[3] = 0x30;
            pad2[4] = x2 as u8;
            pad2[5] = 0x06;
            pad2[6..6 + (x3 + 1)].copy_from_slice(&hash_oid[..x3 + 1]);
            pad2[pad_len - 2] = 0x04;
            pad2[pad_len - 1] = hash_len as u8;
            if pad2[..pad_len] != sig[u..u + pad_len] {
                return 0;
            }
        }
    }
    hash_out[..hash_len].copy_from_slice(&sig[sig_len - hash_len..sig_len]);
    1
}
