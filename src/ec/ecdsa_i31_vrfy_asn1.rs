/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ECDSA signature verification, "i31" implementation, "asn1" format
//! (`src/ec/ecdsa_i31_vrfy_asn1.c`).

use super::{
    br_ec_impl, br_ec_public_key, br_ecdsa_asn1_to_raw, br_ecdsa_i31_vrfy_raw, BR_MAX_EC_SIZE,
};

const FIELD_LEN: usize = (BR_MAX_EC_SIZE + 7) >> 3;

/// see bearssl_ec.h
pub fn br_ecdsa_i31_vrfy_asn1(
    impl_: &br_ec_impl,
    hash: &[u8],
    pk: &br_ec_public_key,
    sig: &[u8],
) -> u32 {
    /*
     * Double-sized buffer because a malformed ASN.1 signature may trigger a
     * size expansion when converting to "raw" format.
     */
    let mut rsig = [0u8; (FIELD_LEN << 2) + 24];

    let sig_len = sig.len();
    if sig_len > (rsig.len() >> 1) {
        return 0;
    }
    rsig[..sig_len].copy_from_slice(sig);
    let raw_len = br_ecdsa_asn1_to_raw(&mut rsig, sig_len);
    br_ecdsa_i31_vrfy_raw(impl_, hash, pk, &rsig[..raw_len])
}
