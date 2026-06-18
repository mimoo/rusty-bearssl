/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! EC private key PKCS#8 DER encoding (`src/x509/encode_ec_pk8der.c`).
//!
//! Wraps the "raw DER" `ECPrivateKey` in an unencrypted PKCS#8
//! `OneAsymmetricKey` whose algorithm is id-ecPublicKey with the curve OID as
//! parameters. Faithful port of `br_encode_ec_pkcs8_der`.

use crate::ec::{br_ec_private_key, br_ec_public_key};
use crate::x509::asn1enc::{br_asn1_encode_length, len_of_len};
use crate::x509::encode_ec_rawder::{br_encode_ec_raw_der_inner, br_get_curve_OID};

/// OID id-ecPublicKey (1.2.840.10045.2.1), DER-encoded (with the tag).
static OID_ECPUBKEY: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// see bearssl_x509.h (`br_encode_ec_pkcs8_der`).
///
/// Returns 0 if the curve is unsupported. With `dest = None` only the encoded
/// length is computed and returned.
pub fn br_encode_ec_pkcs8_der(
    dest: Option<&mut [u8]>,
    sk: &br_ec_private_key,
    pk: Option<&br_ec_public_key>,
) -> usize {
    let oid = match br_get_curve_OID(sk.curve) {
        None => return 0,
        Some(o) => o,
    };
    let olen = oid[0] as usize;

    let len_version = 3usize;
    let len_private_key_algorithm = 2 + OID_ECPUBKEY.len() + 2 + olen;
    let len_private_key_value = br_encode_ec_raw_der_inner(None, sk, pk, false);
    let len_private_key = 1 + len_of_len(len_private_key_value) + len_private_key_value;
    let len_seq = len_version + len_private_key_algorithm + len_private_key;

    match dest {
        None => 1 + len_of_len(len_seq) + len_seq,
        Some(buf) => {
            buf[0] = 0x30; // SEQUENCE tag
            let lenlen = br_asn1_encode_length(Some(&mut buf[1..]), len_seq);
            let mut p = 1 + lenlen;

            // version
            buf[p] = 0x02;
            buf[p + 1] = 0x01;
            buf[p + 2] = 0x00;
            p += 3;

            // privateKeyAlgorithm
            buf[p] = 0x30;
            buf[p + 1] = (OID_ECPUBKEY.len() + 2 + olen) as u8;
            p += 2;
            buf[p..p + OID_ECPUBKEY.len()].copy_from_slice(&OID_ECPUBKEY);
            p += OID_ECPUBKEY.len();
            buf[p] = 0x06;
            p += 1;
            buf[p..p + 1 + olen].copy_from_slice(&oid[..1 + olen]);
            p += 1 + olen;

            // privateKey
            buf[p] = 0x04;
            p += 1;
            p += br_asn1_encode_length(Some(&mut buf[p..]), len_private_key_value);
            br_encode_ec_raw_der_inner(Some(&mut buf[p..]), sk, pk, false);

            1 + lenlen + len_seq
        }
    }
}
