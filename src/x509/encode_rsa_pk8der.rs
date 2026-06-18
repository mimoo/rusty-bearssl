/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! RSA private key PKCS#8 DER encoding (`src/x509/encode_rsa_pk8der.c`).
//!
//! Wraps the "raw DER" `RSAPrivateKey` in an unencrypted PKCS#8
//! `OneAsymmetricKey`. Faithful port of `br_encode_rsa_pkcs8_der`.

use crate::rsa::{br_rsa_private_key, br_rsa_public_key};
use crate::x509::asn1enc::{br_asn1_encode_length, len_of_len};
use crate::x509::encode_rsa_rawder::br_encode_rsa_raw_der;

/// Concatenation of:
///  - DER encoding of an INTEGER of value 0 (the 'version' field)
///  - DER encoding of a PrivateKeyAlgorithmIdentifier using the rsaEncryption
///    OID, with NULL parameters
///  - An OCTET STRING tag
static PK8_HEAD: [u8; 19] = [
    0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04,
];

/// see bearssl_x509.h (`br_encode_rsa_pkcs8_der`).
///
/// With `dest = None` only the encoded length is computed and returned.
pub fn br_encode_rsa_pkcs8_der(
    dest: Option<&mut [u8]>,
    sk: &br_rsa_private_key,
    pk: &br_rsa_public_key,
    d: &[u8],
) -> usize {
    let len_raw = br_encode_rsa_raw_der(None, sk, pk, d);
    let len_seq = PK8_HEAD.len() + len_of_len(len_raw) + len_raw;
    match dest {
        None => 1 + len_of_len(len_seq) + len_seq,
        Some(buf) => {
            buf[0] = 0x30; // SEQUENCE tag
            let lenlen = br_asn1_encode_length(Some(&mut buf[1..]), len_seq);
            let mut p = 1 + lenlen;

            // version, privateKeyAlgorithm, privateKey tag
            buf[p..p + PK8_HEAD.len()].copy_from_slice(&PK8_HEAD);
            p += PK8_HEAD.len();

            // privateKey
            p += br_asn1_encode_length(Some(&mut buf[p..]), len_raw);
            br_encode_rsa_raw_der(Some(&mut buf[p..]), sk, pk, d);

            1 + lenlen + len_seq
        }
    }
}
