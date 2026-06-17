//! HMAC (RFC 4231) and HKDF (RFC 5869) known-answer tests.

use bearssl::hash::{br_sha1_vtable, br_sha256_vtable};
use bearssl::kdf::*;
use bearssl::mac::*;

fn hmac(dig: &'static bearssl::hash::br_hash_class, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, dig, key, key.len());
    let mut ctx = br_hmac_context::new(&kc, 0);
    br_hmac_update(&mut ctx, msg, msg.len());
    let mut out = vec![0u8; br_hmac_size(&ctx)];
    br_hmac_out(&ctx, &mut out);
    out
}

#[test]
fn hmac_sha256_rfc4231() {
    // RFC 4231 test case 1.
    let key = [0x0b; 20];
    assert_eq!(
        hex::encode(hmac(&br_sha256_vtable, &key, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // RFC 4231 test case 2.
    assert_eq!(
        hex::encode(hmac(&br_sha256_vtable, b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn hmac_sha1_rfc2202() {
    // RFC 2202 HMAC-SHA1 test case 2.
    assert_eq!(
        hex::encode(hmac(&br_sha1_vtable, b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
}

#[test]
fn hmac_long_key() {
    // Key longer than the block size must be hashed first (RFC 4231 case 6).
    let key = [0xaa; 131];
    assert_eq!(
        hex::encode(hmac(
            &br_sha256_vtable,
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn hmac_truncated_output() {
    // out_len smaller than natural length truncates.
    let key = [0x0b; 20];
    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, &br_sha256_vtable, &key, key.len());
    let mut ctx = br_hmac_context::new(&kc, 16);
    br_hmac_update(&mut ctx, b"Hi There", 8);
    let mut out = [0u8; 16];
    let n = br_hmac_out(&ctx, &mut out);
    assert_eq!(n, 16);
    assert_eq!(hex::encode(out), "b0344c61d8db38535ca8afceaf0bf12b");
}

#[test]
fn hmac_outct_matches_plain() {
    // Constant-time output must equal the plain output for any length in range.
    let key = [0x0b; 20];
    let msg = b"The quick brown fox jumps over the lazy dog";
    let plain = hmac(&br_sha256_vtable, &key, msg);

    // The CT routine may read up to max_len bytes from the buffer, so the
    // buffer must hold max_len bytes (here we pad to 64); only `len` are real.
    let max_len = 64usize;
    let mut buf = vec![0u8; max_len];
    buf[..msg.len()].copy_from_slice(msg);

    let mut kc = br_hmac_key_context::default();
    br_hmac_key_init(&mut kc, &br_sha256_vtable, &key, key.len());
    let ctx = br_hmac_context::new(&kc, 0);
    let mut out = vec![0u8; 32];
    let n = br_hmac_outCT(&ctx, &buf, msg.len(), 0, max_len, &mut out);
    assert_eq!(n, 32);
    assert_eq!(out, plain);
}

#[test]
fn hkdf_rfc5869_case1() {
    // RFC 5869 Test Case 1 (SHA-256).
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let mut hc = br_hkdf_context::default();
    br_hkdf_init(&mut hc, &br_sha256_vtable, &salt, salt.len());
    br_hkdf_inject(&mut hc, &ikm, ikm.len());
    br_hkdf_flip(&mut hc);
    let mut okm = [0u8; 42];
    let n = br_hkdf_produce(&mut hc, &info, info.len(), &mut okm, 42);
    assert_eq!(n, 42);
    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn hkdf_rfc5869_case3_no_salt() {
    // RFC 5869 Test Case 3 (SHA-256, zero-length salt/info).
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let mut hc = br_hkdf_context::default();
    br_hkdf_init_no_salt(&mut hc, &br_sha256_vtable);
    br_hkdf_inject(&mut hc, &ikm, ikm.len());
    br_hkdf_flip(&mut hc);
    let mut okm = [0u8; 42];
    br_hkdf_produce(&mut hc, &[], 0, &mut okm, 42);
    assert_eq!(
        hex::encode(okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn hkdf_produce_chunked() {
    // Producing output in several calls must equal one big call.
    let ikm = [0x0b; 22];
    let salt = [0u8; 13];
    let info = b"chunk-test";

    let one = {
        let mut hc = br_hkdf_context::default();
        br_hkdf_init(&mut hc, &br_sha256_vtable, &salt, salt.len());
        br_hkdf_inject(&mut hc, &ikm, ikm.len());
        br_hkdf_flip(&mut hc);
        let mut o = [0u8; 80];
        br_hkdf_produce(&mut hc, info, info.len(), &mut o, 80);
        o
    };
    let mut hc = br_hkdf_context::default();
    br_hkdf_init(&mut hc, &br_sha256_vtable, &salt, salt.len());
    br_hkdf_inject(&mut hc, &ikm, ikm.len());
    br_hkdf_flip(&mut hc);
    let mut o = [0u8; 80];
    br_hkdf_produce(&mut hc, info, info.len(), &mut o[..30], 30);
    br_hkdf_produce(&mut hc, info, info.len(), &mut o[30..], 50);
    assert_eq!(o, one);
}
