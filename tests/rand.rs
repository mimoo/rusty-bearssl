//! HMAC_DRBG known-answer tests (same vectors as BearSSL test/test_crypto.c).

use bearssl::hash::br_sha256_vtable;
use bearssl::rand::*;

#[test]
fn hmac_drbg_kat() {
    let seed = hex::decode(
        "009A4D6792295A7F730FC3F2B49CBC0F62E862272F01795EDF0D54DB760F156D0DAC04C0322B3A204224",
    )
    .unwrap();
    let ref1 = "9305a46de7ff8eb107194debd3fd48aa20d5e7656cbe0ea69d2a8d4e7c67";
    let ref2 = "c70c78608a3b5be9289be90ef6e81a9e2c1516d5751d2f75f50033e45f73";
    let ref3 = "475e80e992140567fcc3a50dab90fe84bcd7bb03638e9c4656a06f37f650";

    let mut ctx = br_hmac_drbg_context::new(&br_sha256_vtable, &seed);
    let mut tmp = [0u8; 30];
    br_hmac_drbg_generate(&mut ctx, &mut tmp, 30);
    assert_eq!(hex::encode(tmp), ref1);
    br_hmac_drbg_generate(&mut ctx, &mut tmp, 30);
    assert_eq!(hex::encode(tmp), ref2);
    br_hmac_drbg_generate(&mut ctx, &mut tmp, 30);
    assert_eq!(hex::encode(tmp), ref3);
}

#[test]
fn hmac_drbg_via_vtable() {
    // Same KAT but driven through the br_prng_class descriptor + trait object.
    let seed = hex::decode(
        "009A4D6792295A7F730FC3F2B49CBC0F62E862272F01795EDF0D54DB760F156D0DAC04C0322B3A204224",
    )
    .unwrap();
    let mut prng = (br_hmac_drbg_vtable.init)(PrngParams::Hash(&br_sha256_vtable), &seed);
    let mut tmp = [0u8; 30];
    prng.generate(&mut tmp);
    assert_eq!(hex::encode(tmp), "9305a46de7ff8eb107194debd3fd48aa20d5e7656cbe0ea69d2a8d4e7c67");
}

// ---- AES/CTR DRBG -----------------------------------------------------------

use bearssl::symcipher::br_aes_ct_ctr_vtable;

#[test]
fn aesctr_drbg_kat() {
    // Reference output produced by BearSSL's C br_aesctr_drbg over
    // br_aes_ct_ctr_vtable (computed with libbearssl).

    // Empty seed, then 64 bytes.
    let mut ctx = br_aesctr_drbg_context::new(&br_aes_ct_ctr_vtable, &[]);
    let mut t1 = [0u8; 64];
    br_aesctr_drbg_generate(&mut ctx, &mut t1);
    assert_eq!(
        hex::encode(t1),
        "b7d7ab963d568d076299a149e106b8a4eea3f66ca3f8dd948ac4a753d58403f8\
         3bc9dbca918635abe75d1b0496962889e7c2d718d0367b74e39673fc670f1d37"
    );

    // Reseed with "new seed", then 64 bytes.
    br_aesctr_drbg_update(&mut ctx, b"new seed");
    let mut t2 = [0u8; 64];
    br_aesctr_drbg_generate(&mut ctx, &mut t2);
    assert_eq!(
        hex::encode(t2),
        "424167a0d74a9d467f16f4f03b4492f8947218928df449d53bb181f8525ad004\
         fa9e616115ab9fc72c649ce0fa52af82d8593b7d9c5ab8ede3d75a6a6993a865"
    );
    assert_ne!(t1, t2, "output must change after reseed");

    // Fixed seed "abc", 32 bytes.
    let mut c2 = br_aesctr_drbg_context::new(&br_aes_ct_ctr_vtable, b"abc");
    let mut t3 = [0u8; 32];
    br_aesctr_drbg_generate(&mut c2, &mut t3);
    assert_eq!(
        hex::encode(t3),
        "05ae725fe8e8c3aef4ce6d60a44f77d4169a5cc82b9d0a2be2f6e9901ec5a24b"
    );
}

#[test]
fn aesctr_drbg_via_vtable() {
    // Same first KAT, driven through the br_prng_class descriptor + trait object.
    let mut prng =
        (br_aesctr_drbg_vtable.init)(PrngParams::BlockCtr(&br_aes_ct_ctr_vtable), &[]);
    let mut t1 = [0u8; 64];
    prng.generate(&mut t1);
    assert_eq!(
        hex::encode(t1),
        "b7d7ab963d568d076299a149e106b8a4eea3f66ca3f8dd948ac4a753d58403f8\
         3bc9dbca918635abe75d1b0496962889e7c2d718d0367b74e39673fc670f1d37"
    );
}

// ---- system seeder (sysrng) -------------------------------------------------

#[test]
fn sysrng_seeds_and_differs() {
    // The system seeder must succeed and inject entropy. We verify that two
    // freshly-seeded PRNGs produce different output (the OS RNG differs between
    // the two update() calls) and that output is not all-zero.
    let mut name = "";
    let seeder = br_prng_seeder_system(Some(&mut name)).expect("system seeder available");

    let mut a = br_hmac_drbg_context::new(&br_sha256_vtable, b"base");
    let mut b = br_hmac_drbg_context::new(&br_sha256_vtable, b"base");
    assert_eq!(seeder(&mut a), 1, "seeder failed");
    assert_eq!(seeder(&mut b), 1, "seeder failed");

    let mut oa = [0u8; 32];
    let mut ob = [0u8; 32];
    a.generate(&mut oa);
    b.generate(&mut ob);
    assert!(oa.iter().any(|&x| x != 0), "all-zero output");
    assert_ne!(oa, ob, "two OS-seeded PRNGs produced identical output");
}
