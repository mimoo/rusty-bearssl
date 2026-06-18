//! SHAKE128 / SHAKE256 known-answer tests (NIST validation vectors, same as
//! BearSSL test/test_crypto.c KAT_SHAKE128 / KAT_SHAKE256).

use bearssl::kdf::*;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Drive SHAKE three ways for one (message, expected-output) vector:
///   1. inject the whole message at once;
///   2. inject the message one byte at a time;
///   3. produce the output one byte at a time.
fn shake_kat(level: i32, msg: &str, refout: &str) {
    let msg = hx(msg);
    let refout = hx(refout);
    let n = refout.len();

    let mut sc = br_shake_context::new(level);
    br_shake_inject(&mut sc, &msg);
    br_shake_flip(&mut sc);
    let mut out = vec![0u8; n];
    br_shake_produce(&mut sc, &mut out, n);
    assert_eq!(out, refout, "SHAKE{} KAT 1 (one-shot inject)", level);

    let mut sc = br_shake_context::new(level);
    for b in &msg {
        br_shake_inject(&mut sc, std::slice::from_ref(b));
    }
    br_shake_flip(&mut sc);
    let mut out = vec![0u8; n];
    br_shake_produce(&mut sc, &mut out, n);
    assert_eq!(out, refout, "SHAKE{} KAT 2 (byte-wise inject)", level);

    let mut sc = br_shake_context::new(level);
    br_shake_inject(&mut sc, &msg);
    br_shake_flip(&mut sc);
    for (i, e) in refout.iter().enumerate() {
        let mut x = [0u8; 1];
        br_shake_produce(&mut sc, &mut x, 1);
        assert_eq!(x[0], *e, "SHAKE{} KAT 3 (byte-wise produce, byte {})", level, i);
    }
}

#[test]
fn shake128_kat() {
    shake_kat(
        128,
        "e4e932fc9907620ebebffd32b10fda7890a5bc20e5f41d5589882a18c2960e7aafd8730ee697469e5b0abb1d84de92ddba169802e31570374ef9939fde2b960e6b34ac7a65d36bacba4cd33bfa028cbbba486f32367548cb3a36dacf422924d0e0a7e3285ee158a2a42e4b765da3507b56e54998263b2c7b14e7078e35b74127d5d7220018e995e6e1572db5f3e8678357922f1cfd90a5afa6b420c600fd737b136c70e9dd14",
        "459ce4fa824ee1910a678abc77c1f769",
    );
    shake_kat(
        128,
        "18636f702f216b1b9302e59d82192f4e002f82d526c3f04cbd4f9b9f0bcd2535ed7a67d326da66bdf7fc821ef0fff1a905d56c81e4472856863908d104301133ad111e39552cd542ef78d9b35f20419b893f4a93aee848e9f86ae3fd53d27fea7fb1fc69631fa0f3a5ff51267785086ab4f682d42baf394b3b6992e9a0bb58a38ce0692df9bbaf183e18523ee1352c5fad817e0c04a3e1c476be7f5e92f482a6fb29cd4bbf09ea",
        "b7b9db481898f888e5ee4ed629859844",
    );
}

#[test]
fn shake256_kat() {
    shake_kat(
        256,
        "389fe2a4eecdab928818c1aa6f14fabd41b8ff1a246247b05b1b4672171ce1008f922683529f3ad8dca192f268b66679068063b7ed25a1b5129ad4a1fa22c673cc1105d1aad6d82f4138783a9fe07d77451897277ed27e6fefec2cb56eb2494d18a5e7559d7b6fdddf66db4cbc9926fe270901327e70c8241798b4761dd652d49ad434d8d4",
        "50717d9da0d528c3da799a3307ec74fc086a7d45acfb157774ac28e01ecc74f7",
    );
    shake_kat(
        256,
        "719effd45ed3a8394bf6c49b43f35879176a598601bd6f598867f966a38f512d21dc51b1488c162cbdc00301a41a09f2078a26937c652cfe02b8c4c92ddbb23583495ba825ae845eb2425c5b6856bda48c2cafae0c0c2e1764942d94be50da2b5d8b24a23b647a37f124d691d8cefbf76ef8fbc0fbdafb0a74a53aaf9f165075784ab485d4d4",
        "6881babbb48e9eea72eeb3524db56e4efc323f3350b6be3cdb1f9c6826e359da",
    );
}
