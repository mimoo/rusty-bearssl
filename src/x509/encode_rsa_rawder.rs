/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! RSA private key "raw DER" encoding (`src/x509/encode_rsa_rawder.c`).
//!
//! Encodes a PKCS#1 `RSAPrivateKey` (two-prime, CRT form). Faithful port of
//! `br_encode_rsa_raw_der`.

use crate::rsa::{br_rsa_private_key, br_rsa_public_key};
use crate::x509::asn1enc::{
    br_asn1_encode_length, br_asn1_encode_uint, br_asn1_uint_prepare, len_of_len,
};

/// see bearssl_x509.h (`br_encode_rsa_raw_der`).
///
/// ASN.1 format:
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,       -- 0 (two prime factors)
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- d mod (p-1)
///     exponent2         INTEGER,  -- d mod (q-1)
///     coefficient       INTEGER,  -- (inverse of q) mod p
/// }
/// ```
///
/// With `dest = None` only the encoded length is computed and returned.
pub fn br_encode_rsa_raw_der(
    dest: Option<&mut [u8]>,
    sk: &br_rsa_private_key,
    pk: &br_rsa_public_key,
    d: &[u8],
) -> usize {
    // For all INTEGER values, get the pointer and length for the data bytes.
    let num = [
        br_asn1_uint_prepare(&[]),
        br_asn1_uint_prepare(pk.n),
        br_asn1_uint_prepare(pk.e),
        br_asn1_uint_prepare(d),
        br_asn1_uint_prepare(sk.p),
        br_asn1_uint_prepare(sk.q),
        br_asn1_uint_prepare(sk.dp),
        br_asn1_uint_prepare(sk.dq),
        br_asn1_uint_prepare(sk.iq),
    ];

    // Get the length of the SEQUENCE contents.
    let mut slen = 0usize;
    for u in 0..9 {
        let ilen = num[u].asn1len;
        slen += 1 + len_of_len(ilen) + ilen;
    }

    match dest {
        None => 1 + len_of_len(slen) + slen,
        Some(buf) => {
            buf[0] = 0x30; // SEQUENCE tag
            let lenlen = br_asn1_encode_length(Some(&mut buf[1..]), slen);
            let mut p = 1 + lenlen;
            for u in 0..9 {
                p += br_asn1_encode_uint(Some(&mut buf[p..]), num[u]);
            }
            1 + lenlen + slen
        }
    }
}
