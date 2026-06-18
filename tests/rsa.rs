//! RSA i31 tests, using BearSSL's own test keys/vectors from
//! `BearSSL/test/test_crypto.c`.

use bearssl::hash::{br_sha1_vtable, br_sha256_vtable};
use bearssl::rand::br_hmac_drbg_context;
use bearssl::rsa::{
    br_rsa_i31_compute_modulus, br_rsa_i31_compute_pubexp, br_rsa_i31_oaep_decrypt,
    br_rsa_i31_oaep_encrypt, br_rsa_i31_pkcs1_sign, br_rsa_i31_pkcs1_vrfy, br_rsa_i31_private,
    br_rsa_i31_public, br_rsa_i31_pss_sign, br_rsa_i31_pss_vrfy, br_rsa_private_key,
    br_rsa_public_key, BR_HASH_OID_SHA1,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- 1024-bit RSA test key (RSA_N .. RSA_IQ) --------------------------------

const RSA_N: &[u8] = &[
    0xBF, 0xB4, 0xA6, 0x2E, 0x87, 0x3F, 0x9C, 0x8D, 0xA0, 0xC4, 0x2E, 0x7B, 0x59, 0x36, 0x0F, 0xB0,
    0xFF, 0xE1, 0x25, 0x49, 0xE5, 0xE6, 0x36, 0xB0, 0x48, 0xC2, 0x08, 0x6B, 0x77, 0xA7, 0xC0, 0x51,
    0x66, 0x35, 0x06, 0xA9, 0x59, 0xDF, 0x17, 0x7F, 0x15, 0xF6, 0xB4, 0xE5, 0x44, 0xEE, 0x72, 0x3C,
    0x53, 0x11, 0x52, 0xC9, 0xC9, 0x61, 0x4F, 0x92, 0x33, 0x64, 0x70, 0x43, 0x07, 0xF1, 0x3F, 0x7F,
    0x15, 0xAC, 0xF0, 0xC1, 0x54, 0x7D, 0x55, 0xC0, 0x29, 0xDC, 0x9E, 0xCC, 0xE4, 0x1D, 0x11, 0x72,
    0x45, 0xF4, 0xD2, 0x70, 0xFC, 0x34, 0xB2, 0x1F, 0xF3, 0xAD, 0x6A, 0xF0, 0xE5, 0x56, 0x11, 0xF8,
    0x0C, 0x3A, 0x8B, 0x04, 0x46, 0x7C, 0x77, 0xD9, 0x41, 0x1F, 0x40, 0xBE, 0x93, 0x80, 0x9D, 0x23,
    0x75, 0x80, 0x12, 0x26, 0x5A, 0x72, 0x1C, 0xDD, 0x47, 0xB3, 0x2A, 0x33, 0xD8, 0x19, 0x61, 0xE3,
];
const RSA_E: &[u8] = &[0x01, 0x00, 0x01];
const RSA_P: &[u8] = &[
    0xF2, 0xE7, 0x6F, 0x66, 0x2E, 0xC4, 0x03, 0xD4, 0x89, 0x24, 0xCC, 0xE1, 0xCD, 0x3F, 0x01, 0x82,
    0xC1, 0xFB, 0xAF, 0x44, 0xFA, 0xCC, 0x0E, 0xAA, 0x9D, 0x74, 0xA9, 0x65, 0xEF, 0xED, 0x4C, 0x87,
    0xF0, 0xB3, 0xC6, 0xEA, 0x61, 0x85, 0xDE, 0x4E, 0x66, 0xB2, 0x5A, 0x9F, 0x7A, 0x41, 0xC5, 0x66,
    0x57, 0xDF, 0x88, 0xF0, 0xB5, 0xF2, 0xC7, 0x7E, 0xE6, 0x55, 0x21, 0x96, 0x83, 0xD8, 0xAB, 0x57,
];
const RSA_Q: &[u8] = &[
    0xCA, 0x0A, 0x92, 0xBF, 0x58, 0xB0, 0x2E, 0xF6, 0x66, 0x50, 0xB1, 0x48, 0x29, 0x42, 0x86, 0x6C,
    0x98, 0x06, 0x7E, 0xB8, 0xB5, 0x4F, 0xFB, 0xC4, 0xF3, 0xC3, 0x36, 0x91, 0x07, 0xB6, 0xDB, 0xE9,
    0x56, 0x3C, 0x51, 0x7D, 0xB5, 0xEC, 0x0A, 0xA9, 0x7C, 0x66, 0xF9, 0xD8, 0x25, 0xDE, 0xD2, 0x94,
    0x5A, 0x58, 0xF1, 0x93, 0xE4, 0xF0, 0x5F, 0x27, 0xBD, 0x83, 0xC7, 0xCA, 0x48, 0x6A, 0xB2, 0x55,
];
const RSA_DP: &[u8] = &[
    0xAF, 0x97, 0xBE, 0x60, 0x0F, 0xCE, 0x83, 0x36, 0x51, 0x2D, 0xD9, 0x2E, 0x22, 0x41, 0x39, 0xC6,
    0x5C, 0x94, 0xA4, 0xCF, 0x28, 0xBD, 0xFA, 0x9C, 0x3B, 0xD6, 0xE9, 0xDE, 0x56, 0xE3, 0x24, 0x3F,
    0xE1, 0x31, 0x14, 0xCA, 0xBA, 0x55, 0x1B, 0xAF, 0x71, 0x6D, 0xDD, 0x35, 0x0C, 0x1C, 0x1F, 0xA7,
    0x2C, 0x3E, 0xDB, 0xAF, 0xA6, 0xD8, 0x2A, 0x7F, 0x01, 0xE2, 0xE8, 0xB4, 0xF5, 0xFA, 0xDB, 0x61,
];
const RSA_DQ: &[u8] = &[
    0x29, 0xC0, 0x4B, 0x98, 0xFD, 0x13, 0xD3, 0x70, 0x99, 0xAE, 0x1D, 0x24, 0x83, 0x5A, 0x3A, 0xFB,
    0x1F, 0xE3, 0x5F, 0xB6, 0x7D, 0xC9, 0x5C, 0x86, 0xD3, 0xB4, 0xC8, 0x86, 0xE9, 0xE8, 0x30, 0xC3,
    0xA4, 0x4D, 0x6C, 0xAD, 0xA4, 0xB5, 0x75, 0x72, 0x96, 0xC1, 0x94, 0xE9, 0xC4, 0xD1, 0xAA, 0x04,
    0x7C, 0x33, 0x1B, 0x20, 0xEB, 0xD3, 0x7C, 0x66, 0x72, 0xF4, 0x53, 0x8A, 0x0A, 0xB2, 0xF9, 0xCD,
];
const RSA_IQ: &[u8] = &[
    0xE8, 0xEB, 0x04, 0x79, 0xA5, 0xC1, 0x79, 0xDE, 0xD5, 0x49, 0xA1, 0x0B, 0x48, 0xB9, 0x0E, 0x55,
    0x74, 0x2C, 0x54, 0xEE, 0xA8, 0xB0, 0x01, 0xC2, 0xD2, 0x3C, 0x3E, 0x47, 0x3A, 0x7C, 0xC8, 0x3D,
    0x2E, 0x33, 0x54, 0x4D, 0x40, 0x29, 0x41, 0x74, 0xBA, 0xE1, 0x93, 0x09, 0xEC, 0xE0, 0x1B, 0x4D,
    0x1F, 0x2A, 0xCA, 0x4A, 0x0B, 0x5F, 0xE6, 0xBE, 0x59, 0x0A, 0xC4, 0xC9, 0xD9, 0x82, 0xAC, 0xE1,
];

fn rsa_pk() -> br_rsa_public_key<'static> {
    br_rsa_public_key { n: RSA_N, e: RSA_E }
}
fn rsa_sk() -> br_rsa_private_key<'static> {
    br_rsa_private_key {
        n_bitlen: 1024,
        p: RSA_P,
        q: RSA_Q,
        dp: RSA_DP,
        dq: RSA_DQ,
        iq: RSA_IQ,
    }
}

// ---- KAT: public op then private op (from test_RSA_core) --------------------

#[test]
fn rsa_core_kat() {
    let t1 = hex(
        "45A3DC6A106BCD3BD0E48FB579643AA3FF801E5903E80AA9B43A695A8E7F454E\
         93FA208B69995FF7A6D5617C2FEB8E546375A664977A48931842AAE796B5A0D6\
         4393DCA35F3490FC157F5BD83B9D58C2F7926E6AE648A2BD96CAB8FCCD3D35BB1\
         1424AD47D973FF6D69CA774841AEC45DFAE99CCF79893E7047FDE6CB00AA76D",
    );
    let t2 = hex(
        "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003021300906052B0E03021A05000414A94A8FE5CCB19BA61C4C0873D391E987982FBBD3",
    );
    let pk = rsa_pk();
    let sk = rsa_sk();

    let mut t3 = t1.clone();
    assert_eq!(br_rsa_i31_public(&mut t3, &pk), 1);
    assert_eq!(t3, t2, "KAT RSA pub");
    assert_eq!(br_rsa_i31_private(&mut t3, &sk), 1);
    assert_eq!(t3, t1, "KAT RSA priv");
}

// The third C KAT vector is out of range (value = x + n) and must be rejected.
#[test]
fn rsa_core_out_of_range_rejected() {
    let t1 = hex(
        "F27781B9B3B358583A24F9BA6B34EE98B67A5AE8D8D4FA567BA773EB6B85EF88\
         848680640A1E2F5FD117876E5FB928B64C6EFC7E03632A3F4C941E15657C0C70\
         5F3BB8D0B03A0249143674DB1FE6E5406D690BF2DA76EA7FF3AC6FCE12C78012\
         52FAD52D332BE4AB41F9F8CF1728CDF98AB8E8C20E0C350E4F707A6402C01E0B",
    );
    let pk = rsa_pk();
    let mut t3 = t1.clone();
    assert_eq!(br_rsa_i31_public(&mut t3, &pk), 0, "out-of-range must fail");
}

// ---- PKCS#1 v1.5 sign / verify ----------------------------------------------

#[test]
fn rsa_pkcs1_sign_verify_kat() {
    // Known signature (OpenSSL) over SHA-1("test"); the hash value embedded is
    // A94A8FE5CCB19BA61C4C0873D391E987982FBBD3 (= SHA1("test")).
    let sig = hex(
        "45A3DC6A106BCD3BD0E48FB579643AA3FF801E5903E80AA9B43A695A8E7F454E\
         93FA208B69995FF7A6D5617C2FEB8E546375A664977A48931842AAE796B5A0D6\
         4393DCA35F3490FC157F5BD83B9D58C2F7926E6AE648A2BD96CAB8FCCD3D35BB1\
         1424AD47D973FF6D69CA774841AEC45DFAE99CCF79893E7047FDE6CB00AA76D",
    );
    let hv = hex("A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
    let pk = rsa_pk();
    let sk = rsa_sk();

    // Verify the known signature and extract the hash value.
    let mut tmp = [0u8; 20];
    assert_eq!(
        br_rsa_i31_pkcs1_vrfy(&sig, Some(BR_HASH_OID_SHA1), 20, &pk, &mut tmp),
        1
    );
    assert_eq!(&tmp[..], &hv[..], "extracted hash value");

    // Regenerate the signature (PKCS#1 v1.5 is deterministic) and compare.
    let mut t2 = vec![0u8; 128];
    assert_eq!(
        br_rsa_i31_pkcs1_sign(Some(BR_HASH_OID_SHA1), &hv, 20, &sk, &mut t2),
        1
    );
    assert_eq!(t2, sig, "regenerated signature");

    // Round-trip sign->verify with a fresh hash.
    let mut tmp2 = [0u8; 20];
    assert_eq!(
        br_rsa_i31_pkcs1_vrfy(&t2, Some(BR_HASH_OID_SHA1), 20, &pk, &mut tmp2),
        1
    );
    assert_eq!(&tmp2[..], &hv[..]);
}

#[test]
fn rsa_pkcs1_tampered_rejected() {
    let sk = rsa_sk();
    let pk = rsa_pk();
    let hv = hex("A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
    let mut sig = vec![0u8; 128];
    assert_eq!(
        br_rsa_i31_pkcs1_sign(Some(BR_HASH_OID_SHA1), &hv, 20, &sk, &mut sig),
        1
    );
    sig[64] ^= 0x01;
    let mut tmp = [0u8; 20];
    assert_eq!(
        br_rsa_i31_pkcs1_vrfy(&sig, Some(BR_HASH_OID_SHA1), 20, &pk, &mut tmp),
        0,
        "tampered signature must fail"
    );
}

// ---- compute_modulus / round-trips ------------------------------------------

#[test]
fn rsa_compute_modulus_matches_n() {
    let sk = rsa_sk();
    let mut n = vec![0u8; 128];
    let nlen = br_rsa_i31_compute_modulus(Some(&mut n), &sk);
    assert_eq!(nlen, 128);
    assert_eq!(&n[..nlen], RSA_N);
}

#[test]
fn rsa_compute_get_default_selectors_work() {
    use bearssl::rsa::{
        br_rsa_compute_modulus_get_default, br_rsa_compute_privexp_get_default,
        br_rsa_compute_pubexp_get_default,
    };
    let sk = rsa_sk();

    // Modulus selector matches the i31 implementation / the known modulus.
    let modf = br_rsa_compute_modulus_get_default();
    let mut n = vec![0u8; 128];
    assert_eq!(modf(Some(&mut n), &sk), 128);
    assert_eq!(&n[..], RSA_N);

    // Public-exponent selector dispatches to the i31 implementation (identical
    // result on this key; recovery depends on the key's CRT exponents).
    let pubf = br_rsa_compute_pubexp_get_default();
    assert_eq!(pubf(&sk), br_rsa_i31_compute_pubexp(&sk));

    // Private-exponent recomputation produces a non-empty d for e=65537.
    let privf = br_rsa_compute_privexp_get_default();
    let mut d = vec![0u8; 128];
    let dlen = privf(Some(&mut d), &sk, 0x010001);
    assert!(dlen > 0 && dlen <= 128);
}

// ---- OAEP encrypt -> decrypt round-trip -------------------------------------

#[test]
fn rsa_oaep_roundtrip() {
    let pk = rsa_pk();
    let sk = rsa_sk();
    let mut rng = br_hmac_drbg_context::new(&br_sha256_vtable, b"rsa-oaep-seed");

    let msg = b"hello OAEP world";
    let label = b"";
    let mut dst = vec![0u8; 128];
    let elen = br_rsa_i31_oaep_encrypt(&mut rng, &br_sha256_vtable, label, &pk, &mut dst, msg);
    assert_eq!(elen, 128, "encrypted length == modulus length");

    let mut data = dst.clone();
    let mut len = elen;
    let r = br_rsa_i31_oaep_decrypt(&br_sha256_vtable, label, &sk, &mut data, &mut len);
    assert_eq!(r, 1, "OAEP decrypt OK");
    assert_eq!(&data[..len], &msg[..]);
}

// ---- PSS sign -> verify round-trip ------------------------------------------

fn digest(dig: &'static bearssl::hash::br_hash_class, data: &[u8], out: &mut [u8]) {
    let mut hc = (dig.new)();
    hc.update(data);
    hc.out(out);
}

#[test]
fn rsa_pss_roundtrip() {
    let pk = rsa_pk();
    let sk = rsa_sk();
    let mut rng = br_hmac_drbg_context::new(&br_sha256_vtable, b"rsa-pss-seed");

    // Hash a message with SHA-256.
    let mut hv = [0u8; 32];
    digest(&br_sha256_vtable, b"PSS message", &mut hv);

    let salt_len = 32usize;
    let mut sig = vec![0u8; 128];
    let r = br_rsa_i31_pss_sign(
        Some(&mut rng),
        &br_sha256_vtable,
        &br_sha256_vtable,
        &hv,
        salt_len,
        &sk,
        &mut sig,
    );
    assert_eq!(r, 1, "PSS sign OK");

    let v = br_rsa_i31_pss_vrfy(
        &sig,
        &br_sha256_vtable,
        &br_sha256_vtable,
        &hv,
        salt_len,
        &pk,
    );
    assert_eq!(v, 1, "PSS verify OK");

    // Tamper -> must fail.
    let mut bad = sig.clone();
    bad[40] ^= 0x01;
    let v2 = br_rsa_i31_pss_vrfy(
        &bad,
        &br_sha256_vtable,
        &br_sha256_vtable,
        &hv,
        salt_len,
        &pk,
    );
    assert_eq!(v2, 0, "tampered PSS must fail");
}

#[test]
fn rsa_pss_zero_salt_roundtrip() {
    let pk = rsa_pk();
    let sk = rsa_sk();

    let mut hv = [0u8; 20];
    digest(&br_sha1_vtable, b"no salt", &mut hv);

    let mut sig = vec![0u8; 128];
    let r = br_rsa_i31_pss_sign(None, &br_sha1_vtable, &br_sha1_vtable, &hv, 0, &sk, &mut sig);
    assert_eq!(r, 1);
    let v = br_rsa_i31_pss_vrfy(&sig, &br_sha1_vtable, &br_sha1_vtable, &hv, 0, &pk);
    assert_eq!(v, 1);
}

// ---- keygen (small key) with seeded DRBG ------------------------------------

#[test]
fn rsa_keygen_small() {
    let mut rng = br_hmac_drbg_context::new(&br_sha256_vtable, b"rsa-keygen-seed-1");

    let size = 512usize;
    let mut kbuf_priv = vec![0u8; bearssl::rsa::BR_RSA_KBUF_PRIV_SIZE(size)];
    let mut kbuf_pub = vec![0u8; bearssl::rsa::BR_RSA_KBUF_PUB_SIZE(size)];

    // sk fields are populated from the returned layout afterward.
    let mut sk_tmp = br_rsa_private_key {
        n_bitlen: 0,
        p: &[],
        q: &[],
        dp: &[],
        dq: &[],
        iq: &[],
    };
    let (r, layout) = bearssl::rsa::br_rsa_i31_keygen_inner(
        &mut rng,
        &mut sk_tmp,
        &mut kbuf_priv,
        Some(&mut kbuf_pub),
        size,
        0, // default exponent 3
        bearssl::int::br_i31_modpow_opt,
    );
    assert_eq!(r, 1, "keygen succeeded");
    let lay = layout.unwrap();

    // Build key structs from the buffers using the returned layout.
    let p_off = 0;
    let q_off = p_off + lay.plen;
    let dp_off = q_off + lay.qlen;
    let dq_off = dp_off + lay.dplen;
    let iq_off = dq_off + lay.dqlen;
    let (p, rest) = kbuf_priv.split_at(lay.plen);
    let (q, rest) = rest.split_at(lay.qlen);
    let (dp, rest) = rest.split_at(lay.dplen);
    let (dq, iq) = rest.split_at(lay.dqlen);
    let iq = &iq[..lay.iqlen];
    let _ = (p_off, q_off, dp_off, dq_off, iq_off);

    let sk = br_rsa_private_key {
        n_bitlen: lay.n_bitlen,
        p,
        q,
        dp,
        dq,
        iq,
    };
    let (n, e) = kbuf_pub.split_at(lay.nlen);
    let e = &e[..lay.elen];
    let pk = br_rsa_public_key { n, e };

    // Consistency: sign with the private key, verify with the public key.
    let hv = hex("A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
    let modlen = (size + 7) / 8;
    let mut sig = vec![0u8; modlen];
    assert_eq!(
        br_rsa_i31_pkcs1_sign(Some(BR_HASH_OID_SHA1), &hv, 20, &sk, &mut sig),
        1,
        "sign with generated key"
    );
    let mut tmp = [0u8; 20];
    assert_eq!(
        br_rsa_i31_pkcs1_vrfy(&sig, Some(BR_HASH_OID_SHA1), 20, &pk, &mut tmp),
        1,
        "verify with generated key"
    );
    assert_eq!(&tmp[..], &hv[..]);
}
