//! AES-GCM known-answer tests (canonical McGrew/NIST GCM vectors), driving the
//! ported GCM over the constant-time AES-CTR implementation and `br_ghash_ctmul`.

use bearssl::aead::*;
use bearssl::hash::br_ghash_ctmul;
use bearssl::symcipher::br_aes_ct_ctr_vtable;

fn hx(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn check(key: &str, iv: &str, aad: &str, plain: &str, cipher: &str, tag: &str) {
    let bctx = (br_aes_ct_ctr_vtable.init)(&hx(key));
    let mut ctx = br_gcm_init(bctx, br_ghash_ctmul);
    br_gcm_reset(&mut ctx, &hx(iv));
    let aad = hx(aad);
    br_gcm_aad_inject(&mut ctx, &aad, aad.len());
    br_gcm_flip(&mut ctx);
    let mut data = hx(plain);
    let n = data.len();
    br_gcm_run(&mut ctx, true, &mut data, n);
    let mut t = [0u8; 16];
    br_gcm_get_tag(&mut ctx, &mut t);
    assert_eq!(hex::encode(&data), cipher.replace(char::is_whitespace, ""), "ciphertext");
    assert_eq!(hex::encode(t), tag, "tag");

    // Decrypt path + constant-time tag check.
    let bctx = (br_aes_ct_ctr_vtable.init)(&hx(key));
    let mut ctx = br_gcm_init(bctx, br_ghash_ctmul);
    br_gcm_reset(&mut ctx, &hx(iv));
    br_gcm_aad_inject(&mut ctx, &aad, aad.len());
    br_gcm_flip(&mut ctx);
    let n = data.len();
    br_gcm_run(&mut ctx, false, &mut data, n);
    assert_eq!(hex::encode(&data), plain.replace(char::is_whitespace, ""), "decrypt");
    assert_eq!(br_gcm_check_tag(&mut ctx, &t), 1, "tag verify");
}

#[test]
fn gcm_nist_case2() {
    check(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
}

#[test]
fn gcm_nist_case3_no_aad() {
    check(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    );
}

#[test]
fn gcm_nist_case4_with_aad() {
    check(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    );
}

#[test]
fn gcm_long_iv() {
    // 8-byte nonce path (len != 12) which goes through the GHASH-derived J0.
    check(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbad",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        "3612d2e79e3b0785561be14aaca2fccb",
    );
}

// ---- AES-CCM (RFC 3610 test vectors) ----------------------------------------

use bearssl::symcipher::br_aes_ct_ctrcbc_vtable;

#[test]
fn ccm_rfc3610_packet1() {
    let key = hx("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let nonce = hx("00000003020100a0a1a2a3a4a5");
    let aad = hx("0001020304050607");
    let plain = hx("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    let exp_ct = "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384";
    let exp_tag = "17e8d12cfdf926e0";

    let bctx = (br_aes_ct_ctrcbc_vtable.init)(&key);
    let mut ctx = br_ccm_init(bctx);
    assert!(br_ccm_reset(&mut ctx, &nonce, aad.len() as u64, plain.len() as u64, 8));
    br_ccm_aad_inject(&mut ctx, &aad);
    br_ccm_flip(&mut ctx);
    let mut data = plain.clone();
    br_ccm_run(&mut ctx, true, &mut data);
    let mut tag = [0u8; 8];
    let tl = br_ccm_get_tag(&mut ctx, &mut tag);
    assert_eq!(tl, 8);
    assert_eq!(hex::encode(&data), exp_ct, "ccm ciphertext");
    assert_eq!(hex::encode(tag), exp_tag, "ccm tag");

    // Decrypt + verify.
    let bctx = (br_aes_ct_ctrcbc_vtable.init)(&key);
    let mut ctx = br_ccm_init(bctx);
    br_ccm_reset(&mut ctx, &nonce, aad.len() as u64, data.len() as u64, 8);
    br_ccm_aad_inject(&mut ctx, &aad);
    br_ccm_flip(&mut ctx);
    br_ccm_run(&mut ctx, false, &mut data);
    assert_eq!(hex::encode(&data), hex::encode(&plain), "ccm decrypt");
    assert_eq!(br_ccm_check_tag(&mut ctx, &tag), 1, "ccm tag verify");
}

// ---- EAX (test vectors from the EAX specification / BearSSL KAT_EAX) ---------

fn eax_check(plain: &str, key: &str, nonce: &str, aad: &str, cipher: &str, tag: &str) {
    // Encrypt + tag.
    let bctx = (br_aes_ct_ctrcbc_vtable.init)(&hx(key));
    let mut ctx = br_eax_init(bctx);
    br_eax_reset(&mut ctx, &hx(nonce));
    let aadv = hx(aad);
    br_eax_aad_inject(&mut ctx, &aadv);
    br_eax_flip(&mut ctx);
    let mut data = hx(plain);
    br_eax_run(&mut ctx, true, &mut data);
    let mut t = [0u8; 16];
    br_eax_get_tag(&mut ctx, &mut t);
    assert_eq!(hex::encode(&data), cipher.to_lowercase(), "eax ciphertext");
    assert_eq!(hex::encode(t), tag.to_lowercase(), "eax tag");

    // Decrypt + constant-time tag check.
    let bctx = (br_aes_ct_ctrcbc_vtable.init)(&hx(key));
    let mut ctx = br_eax_init(bctx);
    br_eax_reset(&mut ctx, &hx(nonce));
    br_eax_aad_inject(&mut ctx, &aadv);
    br_eax_flip(&mut ctx);
    br_eax_run(&mut ctx, false, &mut data);
    assert_eq!(hex::encode(&data), plain.to_lowercase(), "eax decrypt");
    assert_eq!(br_eax_check_tag(&mut ctx, &t), 1, "eax tag verify");

    // A corrupted tag must be rejected.
    let mut bad = t;
    bad[0] ^= 0x01;
    let bctx = (br_aes_ct_ctrcbc_vtable.init)(&hx(key));
    let mut ctx = br_eax_init(bctx);
    br_eax_reset(&mut ctx, &hx(nonce));
    br_eax_aad_inject(&mut ctx, &aadv);
    br_eax_flip(&mut ctx);
    let mut data2 = hx(cipher);
    br_eax_run(&mut ctx, false, &mut data2);
    assert_eq!(br_eax_check_tag(&mut ctx, &bad), 0, "eax bad tag rejected");
}

#[test]
fn eax_kat() {
    // (plain, key, nonce, aad, cipher, tag) -- BearSSL KAT_EAX.
    eax_check(
        "",
        "233952dee4d5ed5f9b9c6d6ff80ff478",
        "62ec67f9c3a4a407fcb2a8c49031a8b3",
        "6bfb914fd07eae6b",
        "",
        "e037830e8389f27b025a2d6527e79d01",
    );
    eax_check(
        "f7fb",
        "91945d3f4dcbee0bf45ef52255f095a4",
        "becaf043b0a23d843194ba972c66debd",
        "fa3bfd4806eb53fa",
        "19dd",
        "5c4c9331049d0bdab0277408f67967e5",
    );
    eax_check(
        "1a47cb4933",
        "01f74ad64077f2e704c0f60ada3dd523",
        "70c3db4f0d26368400a10ed05d2bff5e",
        "234a3463c1264ac6",
        "d851d5bae0",
        "3a59f238a23e39199dc9266626c40f80",
    );
    eax_check(
        "481c9e39b1",
        "d07cf6cbb7f313bdde66b727afd3c5e8",
        "8408dfff3c1a2b1292dc199e46b7d617",
        "33cce2eabff5a79d",
        "632a9d131a",
        "d4c168a4225d8e1ff755939974a7bede",
    );
    eax_check(
        "40d0c07da5e4",
        "35b6d0580005bbc12b0587124557d2c2",
        "fdb6b06676eedc5c61d74276e1f8e816",
        "aeb96eaebe2970e9",
        "071dfe16c675",
        "cb0677e536f73afe6a14b74ee49844dd",
    );
    eax_check(
        "4de3b35c3fc039245bd1fb7d",
        "bd8e6e11475e60b268784c38c62feb22",
        "6eac5c93072d8e8513f750935e46da1b",
        "d4482d1ca78dce0f",
        "835bb4f15d743e350e728414",
        "abb8644fd6ccb86947c5e10590210a4f",
    );
    eax_check(
        "8b0a79306c9ce7ed99dae4f87f8dd61636",
        "7c77d6e813bed5ac98baa417477a2e7d",
        "1a8c98dcd73d38393b2bf1569deefc19",
        "65d2017990d62528",
        "02083e3979da014812f59f11d52630da30",
        "137327d10649b0aa6e1c181db617d7f2",
    );
    eax_check(
        "1bda122bce8a8dbaf1877d962b8592dd2d56",
        "5fff20cafab119ca2fc73549e20f5b0d",
        "dde59b97d722156d4d9aff2bc7559826",
        "54b9f04e6a09189a",
        "2ec47b2c4954a489afc7ba4897edcdae8cc3",
        "3b60450599bd02c96382902aef7f832a",
    );
    eax_check(
        "6cf36720872b8513f6eab1a8a44438d5ef11",
        "a4a4782bcffd3ec5e7ef6d8c34a56123",
        "b781fcf2f75fa5a8de97a9ca48e522ec",
        "899a175897561d7e",
        "0de18fd0fdd91e7af19f1d8ee8733938b1e8",
        "e7f6d2231618102fdb7fe55ff1991700",
    );
    eax_check(
        "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
        "8395fcf1e95bebd697bd010bc766aac3",
        "22e7add93cfc6393c57ec0b3c17d6b44",
        "126735fcc320d25a",
        "cb8920f87a6c75cff39627b56e3ed197c552d295a7",
        "cfc46afc253b4652b1af3795b124ab6e",
    );
}
