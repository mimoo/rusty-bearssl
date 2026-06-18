/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! EC private key "raw DER" encoding (`src/x509/encode_ec_rawder.c`).
//!
//! Encodes a SEC1 `ECPrivateKey` (optionally with the curve OID parameters and
//! the public key point). Faithful port of `br_get_curve_OID`,
//! `br_encode_ec_raw_der_inner` and `br_encode_ec_raw_der`.

use crate::ec::{
    br_ec_private_key, br_ec_public_key, BR_EC_secp256r1, BR_EC_secp384r1, BR_EC_secp521r1,
};
use crate::x509::asn1enc::{br_asn1_encode_length, len_of_len};

/// see inner.h (`br_get_curve_OID`).
///
/// Returns the length-prefixed OID bytes (first byte is the OID content length,
/// followed by the OID contents) for a supported NIST curve, or `None`.
pub fn br_get_curve_OID(curve: i32) -> Option<&'static [u8]> {
    static OID_SECP256R1: [u8; 9] = [0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    static OID_SECP384R1: [u8; 6] = [0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    static OID_SECP521R1: [u8; 6] = [0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

    if curve == BR_EC_secp256r1 {
        Some(&OID_SECP256R1)
    } else if curve == BR_EC_secp384r1 {
        Some(&OID_SECP384R1)
    } else if curve == BR_EC_secp521r1 {
        Some(&OID_SECP521R1)
    } else {
        None
    }
}

/// see inner.h (`br_encode_ec_raw_der_inner`).
///
/// `include_curve_oid` selects whether the `[0] parameters` field (the curve
/// OID) is emitted. `pk` is the optional public key point (`[1] publicKey`).
/// Returns 0 if the curve is unsupported when `include_curve_oid` is set.
pub fn br_encode_ec_raw_der_inner(
    dest: Option<&mut [u8]>,
    sk: &br_ec_private_key,
    pk: Option<&br_ec_public_key>,
    include_curve_oid: bool,
) -> usize {
    let oid = if include_curve_oid {
        match br_get_curve_OID(sk.curve) {
            None => return 0,
            Some(o) => Some(o),
        }
    } else {
        None
    };

    let len_version = 3usize;
    let len_private_key = 1 + len_of_len(sk.x.len()) + sk.x.len();
    let len_parameters = if let Some(o) = oid {
        4 + o[0] as usize
    } else {
        0
    };
    let (len_public_key, len_public_key_bits) = match pk {
        None => (0usize, 0usize),
        Some(pk) => {
            let bits = 2 + len_of_len(pk.q.len()) + pk.q.len();
            (1 + len_of_len(bits) + bits, bits)
        }
    };
    let len_seq = len_version + len_private_key + len_parameters + len_public_key;

    let buf = match dest {
        None => return 1 + len_of_len(len_seq) + len_seq,
        Some(buf) => buf,
    };

    buf[0] = 0x30; // SEQUENCE tag
    let lenlen = br_asn1_encode_length(Some(&mut buf[1..]), len_seq);
    let mut p = 1 + lenlen;

    // version
    buf[p] = 0x02;
    buf[p + 1] = 0x01;
    buf[p + 2] = 0x01;
    p += 3;

    // privateKey
    buf[p] = 0x04;
    p += 1;
    p += br_asn1_encode_length(Some(&mut buf[p..]), sk.x.len());
    buf[p..p + sk.x.len()].copy_from_slice(sk.x);
    p += sk.x.len();

    // parameters
    if let Some(o) = oid {
        let olen = o[0] as usize;
        buf[p] = 0xA0;
        buf[p + 1] = (o[0] + 2) as u8;
        buf[p + 2] = 0x06;
        p += 3;
        buf[p..p + olen + 1].copy_from_slice(&o[..olen + 1]);
        p += olen + 1;
    }

    // publicKey
    if let Some(pk) = pk {
        buf[p] = 0xA1;
        p += 1;
        p += br_asn1_encode_length(Some(&mut buf[p..]), len_public_key_bits);
        buf[p] = 0x03;
        p += 1;
        p += br_asn1_encode_length(Some(&mut buf[p..]), pk.q.len() + 1);
        buf[p] = 0x00;
        p += 1;
        buf[p..p + pk.q.len()].copy_from_slice(pk.q);
        // p += pk.q.len();
    }

    1 + lenlen + len_seq
}

/// see bearssl_x509.h (`br_encode_ec_raw_der`).
pub fn br_encode_ec_raw_der(
    dest: Option<&mut [u8]>,
    sk: &br_ec_private_key,
    pk: Option<&br_ec_public_key>,
) -> usize {
    br_encode_ec_raw_der_inner(dest, sk, pk, true)
}
