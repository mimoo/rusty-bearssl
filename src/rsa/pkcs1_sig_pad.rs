/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_pkcs1_sig_pad` (mirrors `src/rsa/rsa_pkcs1_sig_pad.c`).

/// see inner.h
///
/// Build the PKCS#1 v1.5 padded hash value into `x` (length determined by
/// `n_bitlen`). Returns 1 on success, 0 if the modulus is too short.
pub fn br_rsa_pkcs1_sig_pad(
    hash_oid: Option<&[u8]>,
    hash: &[u8],
    hash_len: usize,
    n_bitlen: u32,
    x: &mut [u8],
) -> u32 {
    let xlen = ((n_bitlen + 7) >> 3) as usize;

    let u;
    match hash_oid {
        None => {
            if xlen < hash_len + 11 {
                return 0;
            }
            x[0] = 0x00;
            x[1] = 0x01;
            u = xlen - hash_len;
            for b in x[2..2 + (u - 3)].iter_mut() {
                *b = 0xFF;
            }
            x[u - 1] = 0x00;
        }
        Some(hash_oid) => {
            let x3 = hash_oid[0] as usize;

            // Check that there is enough room for all the elements, including
            // at least eight bytes of value 0xFF.
            if xlen < (x3 + hash_len + 21) {
                return 0;
            }
            x[0] = 0x00;
            x[1] = 0x01;
            let mut u2 = xlen - x3 - hash_len - 11;
            for b in x[2..2 + (u2 - 2)].iter_mut() {
                *b = 0xFF;
            }
            x[u2] = 0x00;
            x[u2 + 1] = 0x30;
            x[u2 + 2] = (x3 + hash_len + 8) as u8;
            x[u2 + 3] = 0x30;
            x[u2 + 4] = (x3 + 4) as u8;
            x[u2 + 5] = 0x06;
            x[u2 + 6..u2 + 6 + (x3 + 1)].copy_from_slice(&hash_oid[..x3 + 1]);
            u2 += x3 + 7;
            x[u2] = 0x05;
            x[u2 + 1] = 0x00;
            x[u2 + 2] = 0x04;
            x[u2 + 3] = hash_len as u8;
            u = u2 + 4;
        }
    }
    x[u..u + hash_len].copy_from_slice(&hash[..hash_len]);
    1
}
