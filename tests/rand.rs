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
    let mut prng = (br_hmac_drbg_vtable.init)(&br_sha256_vtable, &seed);
    let mut tmp = [0u8; 30];
    prng.generate(&mut tmp);
    assert_eq!(hex::encode(tmp), "9305a46de7ff8eb107194debd3fd48aa20d5e7656cbe0ea69d2a8d4e7c67");
}
