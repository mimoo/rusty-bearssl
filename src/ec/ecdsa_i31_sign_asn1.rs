/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ECDSA signature generation, "i31" implementation, "asn1" format
//! (`src/ec/ecdsa_i31_sign_asn1.c`).

use super::{
    br_ec_impl, br_ec_private_key, br_ecdsa_i31_sign_raw, br_ecdsa_raw_to_asn1, BR_MAX_EC_SIZE,
};
use crate::hash::br_hash_class;

const ORDER_LEN: usize = (BR_MAX_EC_SIZE + 7) >> 3;

/// see bearssl_ec.h
pub fn br_ecdsa_i31_sign_asn1(
    impl_: &br_ec_impl,
    hf: &'static br_hash_class,
    hash_value: &[u8],
    sk: &br_ec_private_key,
    sig: &mut [u8],
) -> usize {
    let mut rsig = [0u8; (ORDER_LEN << 1) + 12];

    let mut sig_len = br_ecdsa_i31_sign_raw(impl_, hf, hash_value, sk, &mut rsig);
    if sig_len == 0 {
        return 0;
    }
    sig_len = br_ecdsa_raw_to_asn1(&mut rsig, sig_len);
    sig[..sig_len].copy_from_slice(&rsig[..sig_len]);
    sig_len
}
