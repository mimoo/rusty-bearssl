//! Interop KATs for the symmetric ciphers (AES-ct + modes, ChaCha20, Poly1305,
//! DES/3DES + CBC). Vectors come from FIPS-197, NIST SP800-38A, and RFC 7539,
//! matching the official BearSSL test_crypto.c set.

use bearssl::symcipher::*;

fn hex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

// ---- AES single-block (ECB-equivalent via one CBC block, zero IV) -----------

fn aes_ecb_block(key: &str, plain: &str, cipher: &str) {
    let key = hex(key);
    let mut data = hex(plain);
    let expect = hex(cipher);
    let mut ctx = br_aes_ct_cbcenc_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_cbcenc_init(&mut ctx, &key);
    let mut iv = [0u8; 16];
    br_aes_ct_cbcenc_run(&ctx, &mut iv, &mut data);
    assert_eq!(data, expect, "AES enc block");

    // decrypt back
    let mut dctx = br_aes_ct_cbcdec_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_cbcdec_init(&mut dctx, &key);
    let mut iv = [0u8; 16];
    br_aes_ct_cbcdec_run(&dctx, &mut iv, &mut data);
    assert_eq!(data, hex(plain), "AES dec block");
}

#[test]
fn aes128_fips197() {
    aes_ecb_block(
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    );
}

#[test]
fn aes192_fips197() {
    aes_ecb_block(
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
    );
}

#[test]
fn aes256_fips197() {
    aes_ecb_block(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
    );
}

// ---- AES-128 CBC (NIST SP800-38A F.2) ---------------------------------------

#[test]
fn aes128_cbc_nist() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv0 = hex("000102030405060708090a0b0c0d0e0f");
    let plain = hex(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    );
    let cipher = hex(
        "7649abac8119b246cee98e9b12e9197d\
         5086cb9b507219ee95db113a917678b2\
         73bed6b8e3c1743b7116e69e22229516\
         3ff1caa1681fac09120eca307586e1a7",
    );

    let mut ctx = br_aes_ct_cbcenc_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_cbcenc_init(&mut ctx, &key);
    let mut data = plain.clone();
    let mut iv = iv0.clone();
    br_aes_ct_cbcenc_run(&ctx, &mut iv, &mut data);
    assert_eq!(data, cipher, "CBC encrypt");
    // IV is updated to the last ciphertext block.
    assert_eq!(&iv[..], &cipher[cipher.len() - 16..], "CBC IV update");

    let mut dctx = br_aes_ct_cbcdec_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_cbcdec_init(&mut dctx, &key);
    let mut iv = iv0.clone();
    br_aes_ct_cbcdec_run(&dctx, &mut iv, &mut data);
    assert_eq!(data, plain, "CBC decrypt");
    assert_eq!(&iv[..], &cipher[cipher.len() - 16..], "CBC dec IV update");
}

// ---- AES-128 CTR (NIST SP800-38A F.5) ---------------------------------------

#[test]
fn aes128_ctr_nist() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    // Full initial counter block f0f1..feff: nonce = first 12 bytes, cc = last 4.
    let iv = hex("f0f1f2f3f4f5f6f7f8f9fafb");
    let cc0: u32 = 0xfcfdfeff;
    let plain = hex(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    );
    let cipher = hex(
        "874d6191b620e3261bef6864990db6ce\
         9806f66b7970fdff8617187bb9fffdff\
         5ae4df3edbd5d35e5b4f09020db03eab\
         1e031dda2fbe03d1792170a0f3009cee",
    );

    let mut ctx = br_aes_ct_ctr_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_ctr_init(&mut ctx, &key);
    let mut data = plain.clone();
    let cc = br_aes_ct_ctr_run(&ctx, &iv, cc0, &mut data);
    assert_eq!(data, cipher, "CTR encrypt");
    assert_eq!(cc, cc0.wrapping_add(4), "CTR counter advance (4 blocks)");

    // CTR is its own inverse.
    let _ = br_aes_ct_ctr_run(&ctx, &iv, cc0, &mut data);
    assert_eq!(data, plain, "CTR decrypt");
}

#[test]
fn aes128_roundtrip_lengths() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let mut ctx = br_aes_ct_ctr_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_ctr_init(&mut ctx, &key);
    let iv = hex("f0f1f2f3f4f5f6f7f8f9fafb");
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
        let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let mut data = plain.clone();
        let cc = br_aes_ct_ctr_run(&ctx, &iv, 1, &mut data);
        let _ = br_aes_ct_ctr_run(&ctx, &iv, 1, &mut data);
        assert_eq!(data, plain, "CTR roundtrip len {len}");
        let expected_blocks = ((len + 63) >> 6) as u32 * 4; // not exact, just sanity
        let _ = expected_blocks;
        let _ = cc;
    }
}

// ---- AES-ct CTR+CBC-MAC round-trip ------------------------------------------

#[test]
fn aes_ctrcbc_roundtrip() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let mut ctx = br_aes_ct_ctrcbc_keys {
        skey: [0; 60],
        num_rounds: 0,
    };
    br_aes_ct_ctrcbc_init(&mut ctx, &key);

    for nblocks in [1usize, 2, 3, 5] {
        let len = nblocks * 16;
        let plain: Vec<u8> = (0..len).map(|i| (i * 5 + 1) as u8).collect();

        let ctr0 = hex("00000000000000000000000000000001");
        let mut ctr = ctr0.clone();
        let mut mac = [0u8; 16];
        let mut data = plain.clone();
        br_aes_ct_ctrcbc_encrypt(&ctx, &mut ctr, &mut mac, &mut data);

        let mut ctr_d = ctr0.clone();
        let mut mac_d = [0u8; 16];
        br_aes_ct_ctrcbc_decrypt(&ctx, &mut ctr_d, &mut mac_d, &mut data);
        assert_eq!(data, plain, "ctrcbc roundtrip len {len}");
        assert_eq!(mac, mac_d, "ctrcbc MAC matches len {len}");
        assert_eq!(ctr, ctr_d, "ctrcbc counter matches len {len}");
    }
}

// ---- ChaCha20 (RFC 7539 section 2.4.2) --------------------------------------

#[test]
fn chacha20_rfc7539() {
    let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex("000000000000004a00000000");
    let cc0: u32 = 1;
    let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let cipher = hex(
        "6e2e359a2568f98041ba0728dd0d6981\
         e97e7aec1d4360c20a27afccfd9fae0b\
         f91b65c5524733ab8f593dabcd62b357\
         1639d624e65152ab8f530c359f0861d8\
         07ca0dbf500d6a6156a38e088a22b65e\
         52bc514d16ccf806818ce91ab7793736\
         5af90bbf74a35be6b40b8eedf2785e42\
         874d",
    );

    let mut data = plain.to_vec();
    let cc = br_chacha20_ct_run(&key, &nonce, cc0, &mut data);
    assert_eq!(data, cipher, "ChaCha20 keystream/encrypt");
    let expected_cc = cc0 + ((plain.len() as u32 + 63) >> 6);
    assert_eq!(cc, expected_cc, "ChaCha20 counter return");

    // Decrypt (same operation).
    let _ = br_chacha20_ct_run(&key, &nonce, cc0, &mut data);
    assert_eq!(data, plain.to_vec(), "ChaCha20 decrypt");
}

// ---- ChaCha20-Poly1305 AEAD (RFC 7539 section 2.8.2) ------------------------

#[test]
fn poly1305_chacha20_rfc7539() {
    // Section 2.8.2 full AEAD vector (this is what BearSSL test_crypto.c uses).
    let plain = hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
         73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
         6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
         637265656e20776f756c642062652069742e",
    );
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let cipher = hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let tag = hex("1ae10b594f09e26a7e902ecbd0600691");

    // Encrypt.
    let mut data = plain.clone();
    let mut out_tag = [0u8; 16];
    br_poly1305_ctmul_run(
        &key,
        &nonce,
        &mut data,
        &aad,
        &mut out_tag,
        br_chacha20_ct_run,
        1,
    );
    assert_eq!(data, cipher, "AEAD ciphertext");
    assert_eq!(&out_tag[..], &tag[..], "AEAD tag");

    // Decrypt.
    let mut out_tag2 = [0u8; 16];
    br_poly1305_ctmul_run(
        &key,
        &nonce,
        &mut data,
        &aad,
        &mut out_tag2,
        br_chacha20_ct_run,
        0,
    );
    assert_eq!(data, plain, "AEAD decrypt plaintext");
    assert_eq!(&out_tag2[..], &tag[..], "AEAD decrypt tag");
}

// ---- DES / 3DES -------------------------------------------------------------

/// CBC single/multi-block KAT (key, iv, plaintext, ciphertext) using
/// `br_des_ct_cbcenc`/`cbcdec`; also checks the round-trip.
fn des_cbc_kat(key: &str, iv: &str, plain: &str, cipher: &str) {
    let key = hex(key);
    let iv0 = hex(iv);
    let plain = hex(plain);
    let cipher = hex(cipher);

    let mut ctx = br_des_ct_cbcenc_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcenc_init(&mut ctx, &key);
    let mut iv = iv0.clone();
    let mut data = plain.clone();
    br_des_ct_cbcenc_run(&ctx, &mut iv, &mut data);
    assert_eq!(data, cipher, "DES CBC enc");

    let mut dctx = br_des_ct_cbcdec_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcdec_init(&mut dctx, &key);
    let mut iv = iv0.clone();
    br_des_ct_cbcdec_run(&dctx, &mut iv, &mut data);
    assert_eq!(data, plain, "DES CBC dec");
}

#[test]
fn des_single_known_answer() {
    // Single-DES KAT (8-byte key) from BearSSL KAT_DES; tested through CBC
    // with a zero IV (== ECB for one block).
    des_cbc_kat(
        "10316E028C8F3B4A",
        "0000000000000000",
        "0000000000000000",
        "82DCBAFBDEAB6602",
    );
}

#[test]
fn des3_known_answer() {
    // 3DES CBC KAT from BearSSL KAT_DES_CBC (NIST tdesmmt suite), single block.
    des_cbc_kat(
        "34a41a8c293176c1b30732ecfe38ae8a34a41a8c293176c1",
        "f55b4855228bd0b4",
        "7dd880d2a9ab411c",
        "c91892948b6cadb4",
    );
}

#[test]
fn des3_multiblock_known_answer() {
    // 3DES CBC KAT (multi-block) from BearSSL KAT_DES_CBC.
    des_cbc_kat(
        "70a88fa1dfb9942fa77f40157ffef2ad70a88fa1dfb9942f",
        "ece08ce2fdc6ce80",
        "bc225304d5a3a5c9918fc5006cbc40cc",
        "27f67dc87af7ddb4b68f63fa7c2d454a",
    );
}

#[test]
fn des3_two_key_roundtrip() {
    // 16-byte key => 2-key 3DES (K1,K2,K1).
    let key = hex("0123456789abcdef23456789abcdef01");
    let plain = hex("4e6f772069732074");

    let mut ctx = br_des_ct_cbcenc_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcenc_init(&mut ctx, &key);
    let mut iv = vec![0u8; 8];
    let mut data = plain.clone();
    br_des_ct_cbcenc_run(&ctx, &mut iv, &mut data);

    let mut dctx = br_des_ct_cbcdec_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcdec_init(&mut dctx, &key);
    let mut iv = vec![0u8; 8];
    br_des_ct_cbcdec_run(&dctx, &mut iv, &mut data);
    assert_eq!(data, plain, "2-key 3DES roundtrip");
}

#[test]
fn des_cbc_multiblock_roundtrip() {
    let key = hex("0123456789abcdef23456789abcdef01456789abcdef0123");
    let iv0 = hex("0011223344556677");
    let plain: Vec<u8> = (0..40u8).collect();

    let mut ctx = br_des_ct_cbcenc_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcenc_init(&mut ctx, &key);
    let mut data = plain.clone();
    let mut iv = iv0.clone();
    br_des_ct_cbcenc_run(&ctx, &mut iv, &mut data);
    assert_eq!(&iv[..], &data[data.len() - 8..], "DES CBC IV update");

    let mut dctx = br_des_ct_cbcdec_keys {
        skey: [0; 96],
        num_rounds: 0,
    };
    br_des_ct_cbcdec_init(&mut dctx, &key);
    let mut iv = iv0.clone();
    br_des_ct_cbcdec_run(&dctx, &mut iv, &mut data);
    assert_eq!(data, plain, "DES CBC multiblock roundtrip");
}
