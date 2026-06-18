/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Core TLS PRF P_hash function (`src/ssl/prf.c`).

use super::br_tls_prf_seed_chunk;
use crate::hash::{br_digest_size, br_hash_class};
use crate::mac::{
    br_hmac_context, br_hmac_key_context, br_hmac_key_init, br_hmac_out,
    br_hmac_update,
};

/// see inner.h
///
/// Computes `P_hash(secret, label + seed)` and XORs the result into `dst`.
pub fn br_tls_phash(
    dst: &mut [u8],
    dig: &'static br_hash_class,
    secret: &[u8],
    label: &[u8],
    seed: &[br_tls_prf_seed_chunk],
) {
    let mut len = dst.len();
    if len == 0 {
        return;
    }
    let mut off = 0usize;
    let mut tmp = [0u8; 64];
    let mut a = [0u8; 64];
    let hlen = br_digest_size(dig);

    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, dig, secret, secret.len());

    let mut hc = br_hmac_context::new(&kc, 0);
    br_hmac_update(&mut hc, label, label.len());
    for ch in seed {
        br_hmac_update(&mut hc, ch.data, ch.data.len());
    }
    br_hmac_out(&hc, &mut a);

    loop {
        let mut hc = br_hmac_context::new(&kc, 0);
        br_hmac_update(&mut hc, &a, hlen);
        br_hmac_update(&mut hc, label, label.len());
        for ch in seed {
            br_hmac_update(&mut hc, ch.data, ch.data.len());
        }
        br_hmac_out(&hc, &mut tmp);
        let mut u = 0usize;
        while u < hlen && u < len {
            dst[off + u] ^= tmp[u];
            u += 1;
        }
        off += u;
        len -= u;
        if len == 0 {
            return;
        }
        // A_{i+1} = HMAC(secret, A_i)
        let mut hc = br_hmac_context::new(&kc, 0);
        br_hmac_update(&mut hc, &a, hlen);
        br_hmac_out(&hc, &mut a);
    }
}
