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
