//! TLS 1.2 GCM record-layer round-trip and structure tests.

use bearssl::hash::br_ghash_ctmul;
use bearssl::ssl::*;
use bearssl::symcipher::br_aes_ct_ctr_vtable;

const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const FIXED_IV: [u8; 4] = [0xa0, 0xa1, 0xa2, 0xa3];

#[test]
fn gcm_record_roundtrip() {
    // Encrypt an application-data record (type 23, TLS 1.2 = 0x0303), then
    // decrypt it with a fresh context (same key/IV, same starting sequence).
    let plaintext = b"GET / HTTP/1.1\r\nHost: bearssl\r\n\r\n";
    let len = plaintext.len();

    // Layout: 13 bytes header+nonce space, then plaintext, then 16-byte tag.
    let po = 13;
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(plaintext);

    let mut out =
        br_sslrec_out_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);
    let (off, total) = gcm_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
    // Record = 5-byte header + 8-byte nonce + ciphertext + 16-byte tag.
    assert_eq!(total, 5 + 8 + len + 16);
    assert_eq!(buf[off], 23, "record type");
    assert_eq!(&buf[off + 1..off + 3], &[0x03, 0x03], "version");
    let rec_len = ((buf[off + 3] as usize) << 8) | buf[off + 4] as usize;
    assert_eq!(rec_len, 8 + len + 16, "record length field");
    // Ciphertext must differ from plaintext.
    assert_ne!(&buf[po..po + len], &plaintext[..]);

    // The record payload (after the 5-byte header) is nonce|ct|tag.
    let payload_start = off + 5;
    let payload_len = total - 5;
    let mut payload = buf[payload_start..payload_start + payload_len].to_vec();

    let mut inc =
        br_sslrec_in_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);
    assert!(gcm_check_length(&inc, payload.len()));
    let res = gcm_decrypt(&mut inc, 23, 0x0303, &mut payload);
    let (poff, plen) = res.expect("MAC must verify");
    assert_eq!(plen, len);
    assert_eq!(&payload[poff..poff + plen], &plaintext[..], "recovered plaintext");
}

#[test]
fn gcm_record_tamper_rejected() {
    let plaintext = b"sensitive";
    let len = plaintext.len();
    let po = 13;
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(plaintext);
    let mut out =
        br_sslrec_out_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);
    let (off, total) = gcm_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);

    let payload_start = off + 5;
    let mut payload = buf[payload_start..off + total].to_vec();
    payload[10] ^= 0x01; // flip a ciphertext bit

    let mut inc =
        br_sslrec_in_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);
    assert!(gcm_decrypt(&mut inc, 23, 0x0303, &mut payload).is_none(), "tampered record rejected");
}

#[test]
fn gcm_sequence_numbers_advance() {
    // Two successive records use different nonces (seq 0, then seq 1), so the
    // second decryptor must use seq 1 too.
    let pt = b"hello";
    let len = pt.len();
    let po = 13;

    let mut out =
        br_sslrec_out_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);
    let mut inc =
        br_sslrec_in_gcm_init(&br_aes_ct_ctr_vtable, &KEY, br_ghash_ctmul, &FIXED_IV);

    for _ in 0..3 {
        let mut buf = vec![0u8; po + len + 16];
        buf[po..po + len].copy_from_slice(pt);
        let (off, total) = gcm_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
        let mut payload = buf[off + 5..off + total].to_vec();
        let (poff, plen) = gcm_decrypt(&mut inc, 23, 0x0303, &mut payload).expect("verify");
        assert_eq!(&payload[poff..poff + plen], &pt[..]);
    }
}

// ---- CBC record layer (HMAC-SHA1, AES-128, explicit IV) ---------------------

use bearssl::hash::br_sha1_vtable;
use bearssl::symcipher::{br_aes_ct_cbcdec_vtable, br_aes_ct_cbcenc_vtable};

const CBC_MAC_KEY: [u8; 20] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23,
];

#[test]
fn cbc_record_roundtrip_explicit_iv() {
    // TLS 1.2 (explicit IV) CBC roundtrip with AES-128 + HMAC-SHA1 (mac_len 20).
    // Use the HANDSHAKE record type so no TLS 1.0 1/n-1 split applies.
    let blen = 16usize;
    let mac_len = 20usize;
    let pt = b"a CBC-mode TLS record payload";
    let len = pt.len();

    // Layout (explicit IV): [5 hdr][blen IV][plaintext][mac_len MAC][padding].
    // Padding can be up to blen bytes. Reserve generously and place plaintext at
    // po so that header (5) + IV (blen) fit before it.
    let po = 5 + blen;
    let mut buf = vec![0u8; po + len + mac_len + 2 * blen + 8];
    buf[po..po + len].copy_from_slice(pt);

    let mut out = br_sslrec_out_cbc_init(
        &br_aes_ct_cbcenc_vtable,
        &KEY,
        &br_sha1_vtable,
        &CBC_MAC_KEY,
        mac_len,
        None, // explicit IV
    );
    let (off, total) = cbc_encrypt(&mut out, 22, 0x0303, &mut buf, po, len);
    assert_eq!(buf[off], 22, "record type");
    assert_eq!(&buf[off + 1..off + 3], &[0x03, 0x03], "version");
    let rec_len = ((buf[off + 3] as usize) << 8) | buf[off + 4] as usize;
    // Body = IV + plaintext + MAC + padding, multiple of the block size.
    assert_eq!(rec_len % blen, 0, "record body multiple of block size");
    assert_eq!(total, 5 + rec_len);

    // Decrypt with a fresh context (explicit IV mode).
    let mut payload = buf[off + 5..off + total].to_vec();
    let mut inc = br_sslrec_in_cbc_init(
        &br_aes_ct_cbcdec_vtable,
        &KEY,
        &br_sha1_vtable,
        &CBC_MAC_KEY,
        mac_len,
        None,
    );
    assert!(cbc_check_length(&inc, payload.len()), "check_length");
    let (poff, plen) = cbc_decrypt(&mut inc, 22, 0x0303, &mut payload).expect("MAC verify");
    assert_eq!(plen, len);
    assert_eq!(&payload[poff..poff + plen], &pt[..], "recovered plaintext");
}

#[test]
fn cbc_record_tamper_rejected() {
    let blen = 16usize;
    let mac_len = 20usize;
    let pt = b"do not tamper";
    let len = pt.len();
    let po = 5 + blen;
    let mut buf = vec![0u8; po + len + mac_len + 2 * blen + 8];
    buf[po..po + len].copy_from_slice(pt);
    let mut out = br_sslrec_out_cbc_init(
        &br_aes_ct_cbcenc_vtable,
        &KEY,
        &br_sha1_vtable,
        &CBC_MAC_KEY,
        mac_len,
        None,
    );
    let (off, total) = cbc_encrypt(&mut out, 22, 0x0303, &mut buf, po, len);
    let mut payload = buf[off + 5..off + total].to_vec();
    // Flip a byte in the ciphertext body (after the explicit-IV block).
    payload[blen + 1] ^= 0x01;
    let mut inc = br_sslrec_in_cbc_init(
        &br_aes_ct_cbcdec_vtable,
        &KEY,
        &br_sha1_vtable,
        &CBC_MAC_KEY,
        mac_len,
        None,
    );
    assert!(
        cbc_decrypt(&mut inc, 22, 0x0303, &mut payload).is_none(),
        "tampered CBC record must be rejected"
    );
}

// ---- CCM record layer (AES-128-CCM, 16-byte and 8-byte tags) ----------------

use bearssl::symcipher::br_aes_ct_ctrcbc_vtable;

fn ccm_roundtrip(tag_len: usize) {
    let pt = b"AES-CCM TLS 1.2 record payload!!";
    let len = pt.len();
    // Layout: [13 hdr+nonce][plaintext][tag].
    let po = 13;
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(pt);

    let mut out = br_sslrec_out_ccm_init(&br_aes_ct_ctrcbc_vtable, &KEY, &FIXED_IV, tag_len);
    let (off, total) = ccm_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
    assert_eq!(total, 5 + 8 + len + tag_len);
    assert_eq!(buf[off], 23);
    assert_ne!(&buf[po..po + len], &pt[..]);

    let mut payload = buf[off + 5..off + total].to_vec();
    let mut inc = br_sslrec_in_ccm_init(&br_aes_ct_ctrcbc_vtable, &KEY, &FIXED_IV, tag_len);
    assert!(ccm_check_length(&inc, payload.len()));
    let (poff, plen) = ccm_decrypt(&mut inc, 23, 0x0303, &mut payload).expect("CCM tag verify");
    assert_eq!(plen, len);
    assert_eq!(&payload[poff..poff + plen], &pt[..]);
}

#[test]
fn ccm_record_roundtrip_tag16() {
    ccm_roundtrip(16);
}

#[test]
fn ccm_record_roundtrip_tag8() {
    ccm_roundtrip(8);
}

#[test]
fn ccm_record_tamper_rejected() {
    let pt = b"secret ccm";
    let len = pt.len();
    let po = 13;
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(pt);
    let mut out = br_sslrec_out_ccm_init(&br_aes_ct_ctrcbc_vtable, &KEY, &FIXED_IV, 16);
    let (off, total) = ccm_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
    let mut payload = buf[off + 5..off + total].to_vec();
    payload[9] ^= 0x01;
    let mut inc = br_sslrec_in_ccm_init(&br_aes_ct_ctrcbc_vtable, &KEY, &FIXED_IV, 16);
    assert!(ccm_decrypt(&mut inc, 23, 0x0303, &mut payload).is_none());
}

// ---- ChaCha20-Poly1305 record layer ----------------------------------------

use bearssl::symcipher::{br_chacha20_ct_run, br_poly1305_ctmul_run};

const CHAPOL_KEY: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];
const CHAPOL_IV: [u8; 12] = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

#[test]
fn chapol_record_roundtrip() {
    let pt = b"ChaCha20-Poly1305 TLS record payload, hello!";
    let len = pt.len();
    let po = 5; // record header only (no explicit nonce)
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(pt);

    let mut out = br_sslrec_out_chapol_init(
        br_chacha20_ct_run,
        br_poly1305_ctmul_run,
        &CHAPOL_KEY,
        &CHAPOL_IV,
    );
    let (off, total) = chapol_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
    assert_eq!(total, 5 + len + 16);
    assert_eq!(buf[off], 23);
    assert_ne!(&buf[po..po + len], &pt[..], "ciphertext differs");

    let mut payload = buf[off + 5..off + total].to_vec();
    let mut inc = br_sslrec_in_chapol_init(
        br_chacha20_ct_run,
        br_poly1305_ctmul_run,
        &CHAPOL_KEY,
        &CHAPOL_IV,
    );
    assert!(chapol_check_length(&inc, payload.len()));
    let (poff, plen) = chapol_decrypt(&mut inc, 23, 0x0303, &mut payload).expect("MAC verify");
    assert_eq!(&payload[poff..poff + plen], &pt[..]);
}

#[test]
fn chapol_tamper_rejected() {
    let pt = b"secret";
    let len = pt.len();
    let po = 5;
    let mut buf = vec![0u8; po + len + 16];
    buf[po..po + len].copy_from_slice(pt);
    let mut out = br_sslrec_out_chapol_init(br_chacha20_ct_run, br_poly1305_ctmul_run, &CHAPOL_KEY, &CHAPOL_IV);
    let (off, total) = chapol_encrypt(&mut out, 23, 0x0303, &mut buf, po, len);
    let mut payload = buf[off + 5..off + total].to_vec();
    payload[2] ^= 0x01;
    let mut inc = br_sslrec_in_chapol_init(br_chacha20_ct_run, br_poly1305_ctmul_run, &CHAPOL_KEY, &CHAPOL_IV);
    assert!(chapol_decrypt(&mut inc, 23, 0x0303, &mut payload).is_none());
}
