// Known-answer and cross-family tests for the int (bignum) module.
//
// The four families (i15, i31, i32, i62) implement the same operations over
// different internal representations; a strong correctness signal is that they
// all agree with one another and with independently computed values.

use bearssl::int::*;

// ---- sizing helpers ---------------------------------------------------------
//
// We allocate generously (more than the strict minimum) so that the in-place
// muladd/montmul routines, which may touch one extra word, never run off the
// end.

fn i31_alloc(bits: usize) -> Vec<u32> {
    vec![0u32; 4 + (bits / 31) + 2]
}
fn i32_alloc(bits: usize) -> Vec<u32> {
    vec![0u32; 4 + (bits / 32) + 2]
}
fn i15_alloc(bits: usize) -> Vec<u16> {
    vec![0u16; 4 + (bits / 15) + 2]
}

// Big-endian byte vector of a hex string.
fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// Encode an i31 integer to a big-endian byte buffer of the given length.
fn i31_to_bytes(x: &[u32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    br_i31_encode(&mut out, len, x);
    out
}
fn i32_to_bytes(x: &[u32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    br_i32_encode(&mut out, len, x);
    out
}
fn i15_to_bytes(x: &[u16], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    br_i15_encode(&mut out, len, x);
    out
}

// ---- encode/decode round trips ---------------------------------------------

#[test]
fn encode_decode_roundtrip() {
    let cases = [
        "00",
        "01",
        "ff",
        "0102030405",
        "deadbeefcafebabe",
        "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337",
        "0000000000000001",
    ];
    for c in cases {
        let b = hexb(c);
        let bits = b.len() * 8;

        let mut x31 = i31_alloc(bits);
        br_i31_decode(&mut x31, &b, b.len());
        let r31 = i31_to_bytes(&x31, b.len());
        assert_eq!(r31, b, "i31 roundtrip {c}");

        let mut x32 = i32_alloc(bits);
        br_i32_decode(&mut x32, &b, b.len());
        let r32 = i32_to_bytes(&x32, b.len());
        assert_eq!(r32, b, "i32 roundtrip {c}");

        let mut x15 = i15_alloc(bits);
        br_i15_decode(&mut x15, &b, b.len());
        let r15 = i15_to_bytes(&x15, b.len());
        assert_eq!(r15, b, "i15 roundtrip {c}");
    }
}

// ---- decode_mod -------------------------------------------------------------

// Build a modulus integer for each family from a big-endian byte string.
fn make_mod31(m: &str) -> Vec<u32> {
    let b = hexb(m);
    let mut x = i31_alloc(b.len() * 8);
    br_i31_decode(&mut x, &b, b.len());
    x
}
fn make_mod32(m: &str) -> Vec<u32> {
    let b = hexb(m);
    let mut x = i32_alloc(b.len() * 8);
    br_i32_decode(&mut x, &b, b.len());
    x
}
fn make_mod15(m: &str) -> Vec<u16> {
    let b = hexb(m);
    let mut x = i15_alloc(b.len() * 8);
    br_i15_decode(&mut x, &b, b.len());
    x
}

#[test]
fn decode_mod_fits_and_overflow() {
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let m31 = make_mod31(mhex);
    let m32 = make_mod32(mhex);
    let m15 = make_mod15(mhex);

    // A value strictly below the modulus.
    let vhex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let v = hexb(vhex);

    let mut x31 = i31_alloc(bits);
    assert_eq!(br_i31_decode_mod(&mut x31, &v, v.len(), &m31), 1);
    let mut x32 = i32_alloc(bits);
    assert_eq!(br_i32_decode_mod(&mut x32, &v, v.len(), &m32), 1);
    let mut x15 = i15_alloc(bits);
    assert_eq!(br_i15_decode_mod(&mut x15, &v, v.len(), &m15), 1);

    // All families agree on the (unchanged) value.
    let n = mhex.len() / 2;
    assert_eq!(i31_to_bytes(&x31, n), i32_to_bytes(&x32, n));
    assert_eq!(i31_to_bytes(&x31, n), i15_to_bytes(&x15, n));
    assert_eq!(i31_to_bytes(&x31, n), v);

    // A value equal to the modulus must NOT fit.
    let mb = hexb(mhex);
    let mut y31 = i31_alloc(bits);
    assert_eq!(br_i31_decode_mod(&mut y31, &mb, mb.len(), &m31), 0);
    let mut y32 = i32_alloc(bits);
    assert_eq!(br_i32_decode_mod(&mut y32, &mb, mb.len(), &m32), 0);
    let mut y15 = i15_alloc(bits);
    assert_eq!(br_i15_decode_mod(&mut y15, &mb, mb.len(), &m15), 0);
    // x[] set to 0 on overflow.
    assert!(i31_to_bytes(&y31, n).iter().all(|&b| b == 0));
}

// ---- decode_reduce + reduce -------------------------------------------------

#[test]
fn decode_reduce_matches_expected() {
    // m and a known input; expected = input mod m (computed independently).
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;

    // input larger than the modulus (2x as many bytes)
    let vhex = "feedface0badc0de1122334455667788\
                99aabbccddeeff00feedface0badc0de\
                1122334455667788\
                99aabbccddeeff00feedface0badc0de";
    let v = hexb(vhex);

    // expected = v mod m (computed independently)
    let expected =
        hexb("43ed8a27529656d331896d1206f58011896a6016215c1ad2210eceb4907706ff");

    let m31 = make_mod31(mhex);
    let m32 = make_mod32(mhex);
    let m15 = make_mod15(mhex);

    let mut x31 = i31_alloc(bits);
    br_i31_decode_reduce(&mut x31, &v, v.len(), &m31);
    let mut x32 = i32_alloc(bits);
    br_i32_decode_reduce(&mut x32, &v, v.len(), &m32);
    let mut x15 = i15_alloc(bits);
    br_i15_decode_reduce(&mut x15, &v, v.len(), &m15);

    // Cross-family agreement is the primary assertion.
    let r31 = i31_to_bytes(&x31, n);
    assert_eq!(r31, i32_to_bytes(&x32, n), "i31 vs i32 decode_reduce");
    assert_eq!(r31, i15_to_bytes(&x15, n), "i31 vs i15 decode_reduce");
    // And the independently computed value.
    assert_eq!(r31, expected, "decode_reduce value");

    // br_i31_reduce of the decoded full value should match decode_reduce.
    let mut a31 = i31_alloc(v.len() * 8);
    br_i31_decode(&mut a31, &v, v.len());
    let mut red = i31_alloc(bits);
    br_i31_reduce(&mut red, &a31, &m31);
    assert_eq!(i31_to_bytes(&red, n), r31, "reduce vs decode_reduce");
}

// ---- Montgomery multiplication consistency ----------------------------------

// Compute m0i for the i31 family.
fn m0i31(m: &[u32]) -> u32 {
    br_i31_ninv31(m[1])
}
fn m0i32(m: &[u32]) -> u32 {
    br_i32_ninv32(m[1])
}
fn m0i15(m: &[u16]) -> u16 {
    br_i15_ninv15(m[1])
}

#[test]
fn montmul_to_from_roundtrip() {
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m31 = make_mod31(mhex);
    let m0i = m0i31(&m31);

    let vhex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let v = hexb(vhex);
    let mut x = i31_alloc(bits);
    assert_eq!(br_i31_decode_mod(&mut x, &v, v.len(), &m31), 1);
    let orig = i31_to_bytes(&x, n);

    // to_monty then from_monty is the identity.
    br_i31_to_monty(&mut x, &m31);
    br_i31_from_monty(&mut x, &m31, m0i);
    assert_eq!(i31_to_bytes(&x, n), orig, "to/from monty roundtrip");
}

#[test]
fn montmul_computes_product() {
    // montmul(x,y) in Montgomery domain then convert back == x*y mod m.
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m31 = make_mod31(mhex);
    let m0i = m0i31(&m31);

    let xb = hexb("000000000000000000000000000000000000000000000000000deadbeef12345");
    let yb = hexb("0000000000000000000000000000000000000000000000000000cafebabe6789");
    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &xb, xb.len(), &m31);
    let mut y = i31_alloc(bits);
    br_i31_decode_reduce(&mut y, &yb, yb.len(), &m31);

    // To Montgomery, multiply, from Montgomery.
    br_i31_to_monty(&mut x, &m31);
    br_i31_to_monty(&mut y, &m31);
    let mut d = i31_alloc(bits);
    br_i31_montymul(&mut d, &x, &y, &m31, m0i);
    br_i31_from_monty(&mut d, &m31, m0i);

    // expected = x*y mod m = 0xb092ab7bf14dd27e43372a2ed
    let mut exp = vec![0u8; n];
    let e = hexb("0b092ab7bf14dd27e43372a2ed");
    exp[n - e.len()..].copy_from_slice(&e);
    assert_eq!(i31_to_bytes(&d, n), exp, "montmul product");
}

// ---- modular exponentiation -------------------------------------------------

// Run br_i31_modpow with appropriately sized temporaries.
fn modpow31(mhex: &str, basehex: &str, e: &[u8]) -> Vec<u8> {
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod31(mhex);
    let m0i = m0i31(&m);
    let bb = hexb(basehex);
    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &bb, bb.len(), &m);
    let mut t1 = i31_alloc(bits);
    let mut t2 = i31_alloc(bits);
    br_i31_modpow(&mut x, e, e.len(), &m, m0i, &mut t1, &mut t2);
    i31_to_bytes(&x, n)
}
fn modpow32(mhex: &str, basehex: &str, e: &[u8]) -> Vec<u8> {
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod32(mhex);
    let m0i = m0i32(&m);
    let bb = hexb(basehex);
    let mut x = i32_alloc(bits);
    br_i32_decode_reduce(&mut x, &bb, bb.len(), &m);
    let mut t1 = i32_alloc(bits);
    let mut t2 = i32_alloc(bits);
    br_i32_modpow(&mut x, e, e.len(), &m, m0i, &mut t1, &mut t2);
    i32_to_bytes(&x, n)
}
fn modpow15(mhex: &str, basehex: &str, e: &[u8]) -> Vec<u8> {
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod15(mhex);
    let m0i = m0i15(&m);
    let bb = hexb(basehex);
    let mut x = i15_alloc(bits);
    br_i15_decode_reduce(&mut x, &bb, bb.len(), &m);
    let mut t1 = i15_alloc(bits);
    let mut t2 = i15_alloc(bits);
    br_i15_modpow(&mut x, e, e.len(), &m, m0i, &mut t1, &mut t2);
    i15_to_bytes(&x, n)
}

#[test]
fn modpow_small_known_answer() {
    // Small modulus where we can verify by hand via u128.
    // m = 0xFFFFFFFB (prime-ish, odd), base = 0x12345, e = 0x10001.
    let m: u128 = 0xFFFF_FFFB;
    let base: u128 = 0x12345;
    let e: u128 = 0x10001;
    let mut expected = 1u128;
    let mut b = base % m;
    let mut ee = e;
    while ee > 0 {
        if ee & 1 == 1 {
            expected = (expected * b) % m;
        }
        b = (b * b) % m;
        ee >>= 1;
    }

    let mhex = "fffffffb";
    let basehex = "00012345";
    let ebytes = [0x01u8, 0x00, 0x01];

    let r31 = modpow31(mhex, basehex, &ebytes);
    let r32 = modpow32(mhex, basehex, &ebytes);
    let r15 = modpow15(mhex, basehex, &ebytes);

    let mut exp = vec![0u8; 4];
    exp.copy_from_slice(&(expected as u32).to_be_bytes());
    assert_eq!(r31, exp, "i31 small modpow");
    assert_eq!(r32, exp, "i32 small modpow");
    assert_eq!(r15, exp, "i15 small modpow");
}

#[test]
fn modpow_rsa_like_cross_family() {
    // 256-bit odd modulus; e = 65537. Cross-check the three families against
    // each other and against an independently computed value.
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let basehex = "000000000000000000000000000000000000000000000000123456789abcdef0";
    let ebytes = [0x01u8, 0x00, 0x01];

    let r31 = modpow31(mhex, basehex, &ebytes);
    let r32 = modpow32(mhex, basehex, &ebytes);
    let r15 = modpow15(mhex, basehex, &ebytes);

    assert_eq!(r31, r32, "i31 vs i32 modpow");
    assert_eq!(r31, r15, "i31 vs i15 modpow");

    let expected =
        hexb("a26b33b22ce76eb88afe53286d2106418af70ce1a07c498c67544289aebd8a08");
    assert_eq!(r31, expected, "rsa-like modpow value");
}

#[test]
fn modpow_opt_matches_modpow() {
    // br_i31_modpow_opt with a large tmp (windowed) must equal br_i31_modpow.
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod31(mhex);
    let m0i = m0i31(&m);
    let basehex = "000000000000000000000000000000000000000000000000123456789abcdef0";
    let bb = hexb(basehex);
    let e = [0x01u8, 0x00, 0x01];

    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &bb, bb.len(), &m);
    // Generous temporary buffer to allow a >1-bit window.
    let mut tmp = vec![0u32; 64 * (bits / 31 + 4)];
    let twlen = tmp.len();
    assert_eq!(
        br_i31_modpow_opt(&mut x, &e, e.len(), &m, m0i, &mut tmp, twlen),
        1
    );
    let ropt = i31_to_bytes(&x, n);

    let rbasic = modpow31(mhex, basehex, &e);
    assert_eq!(ropt, rbasic, "modpow_opt vs modpow");
}

#[test]
fn modpow2_i15_matches() {
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod15(mhex);
    let m0i = m0i15(&m);
    let basehex = "000000000000000000000000000000000000000000000000123456789abcdef0";
    let bb = hexb(basehex);
    let e = [0x01u8, 0x00, 0x01];

    let mut x = i15_alloc(bits);
    br_i15_decode_reduce(&mut x, &bb, bb.len(), &m);
    let mut tmp = vec![0u16; 64 * (bits / 15 + 4)];
    let twlen = tmp.len();
    assert_eq!(
        br_i15_modpow_opt(&mut x, &e, e.len(), &m, m0i, &mut tmp, twlen),
        1
    );
    let ropt = i15_to_bytes(&x, n);
    assert_eq!(ropt, modpow15(mhex, basehex, &e), "i15 modpow_opt vs modpow");
}

// ---- i62 modpow -------------------------------------------------------------

#[test]
fn i62_modpow_matches_i31() {
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod31(mhex);
    let m0i = m0i31(&m);
    let basehex = "000000000000000000000000000000000000000000000000123456789abcdef0";
    let bb = hexb(basehex);
    let e = [0x01u8, 0x00, 0x01];

    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &bb, bb.len(), &m);

    // 64-bit temporaries; generous size for windowing.
    let mut tmp = vec![0u64; 64 * (bits / 31 + 8)];
    let twlen = tmp.len();
    assert_eq!(
        br_i62_modpow_opt(&mut x, &e, e.len(), &m, m0i, &mut tmp, twlen),
        1
    );
    let r62 = i31_to_bytes(&x, n);
    assert_eq!(r62, modpow31(mhex, basehex, &e), "i62 modpow vs i31 modpow");
}

#[test]
fn i62_modpow_fallback_small_modulus() {
    // For a small modulus (< 4 words) i62 falls back to i31_modpow internally.
    let mhex = "fffffffb";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;
    let m = make_mod31(mhex);
    let m0i = m0i31(&m);
    let basehex = "00012345";
    let bb = hexb(basehex);
    let e = [0x01u8, 0x00, 0x01];

    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &bb, bb.len(), &m);
    let mut tmp = vec![0u64; 64];
    let twlen = tmp.len();
    assert_eq!(
        br_i62_modpow_opt(&mut x, &e, e.len(), &m, m0i, &mut tmp, twlen),
        1
    );
    assert_eq!(i31_to_bytes(&x, n), modpow31(mhex, basehex, &e));
}

// ---- modular division -------------------------------------------------------

#[test]
fn moddiv_known_answer() {
    // x/y mod m, cross-family + independent value.
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let bits = mhex.len() * 4;
    let n = mhex.len() / 2;

    let xhex = "00000000000000000000000000000000000000000000000000000deadbeef12345";
    let yhex = "000000000000000000000000000000000000000000000000000000cafebabe6789";

    // ---- i31 ----
    let m31 = make_mod31(mhex);
    let m0i = m0i31(&m31);
    let xb = hexb(xhex);
    let yb = hexb(yhex);
    let mut x = i31_alloc(bits);
    br_i31_decode_reduce(&mut x, &xb, xb.len(), &m31);
    let mut y = i31_alloc(bits);
    br_i31_decode_reduce(&mut y, &yb, yb.len(), &m31);
    let mut t = vec![0u32; 4 * (bits / 31 + 4)];
    assert_eq!(br_i31_moddiv(&mut x, &y, &m31, m0i, &mut t), 1, "moddiv ok");
    let r31 = i31_to_bytes(&x, n);

    // ---- i15 ----
    let m15 = make_mod15(mhex);
    let m0i15v = m0i15(&m15);
    let mut x15 = i15_alloc(bits);
    br_i15_decode_reduce(&mut x15, &xb, xb.len(), &m15);
    let mut y15 = i15_alloc(bits);
    br_i15_decode_reduce(&mut y15, &yb, yb.len(), &m15);
    let mut t15 = vec![0u16; 4 * (bits / 15 + 4)];
    assert_eq!(br_i15_moddiv(&mut x15, &y15, &m15, m0i15v, &mut t15), 1);
    let r15 = i15_to_bytes(&x15, n);

    assert_eq!(r31, r15, "moddiv i31 vs i15");

    let expected =
        hexb("5f015f5aa001a8c2acff1913aeb6b93538946aa6de69c84e927736f8e720b881");
    assert_eq!(r31, expected, "moddiv value");
}

// ---- add / sub / mulacc -----------------------------------------------------

#[test]
fn add_sub_carry() {
    // a = 0x7FFFFFFF... ; add 1 with ctl; check carry behaviour matches across
    // i31 and i32 by comparing the encoded results.
    let ahex = "00000001fffffffffffffffe";
    let bhex = "000000000000000000000002";
    let bits = ahex.len() * 4;
    let n = ahex.len() / 2;

    let mut a31 = i31_alloc(bits);
    br_i31_decode(&mut a31, &hexb(ahex), n);
    let mut b31 = i31_alloc(bits);
    br_i31_decode(&mut b31, &hexb(bhex), n);
    // Make b have the same announced bit length as a (add requires it).
    b31[0] = a31[0];
    br_i31_add(&mut a31, &b31, 1);
    let r31 = i31_to_bytes(&a31, n);

    let mut a32 = i32_alloc(bits);
    br_i32_decode(&mut a32, &hexb(ahex), n);
    let mut b32 = i32_alloc(bits);
    br_i32_decode(&mut b32, &hexb(bhex), n);
    b32[0] = a32[0];
    br_i32_add(&mut a32, &b32, 1);
    let r32 = i32_to_bytes(&a32, n);

    assert_eq!(r31, r32, "add i31 vs i32");
    // 0x1fffffffffffffffe + 2 = 0x20000000000000000
    assert_eq!(r31, hexb("000000020000000000000000"));

    // Now subtract back.
    br_i31_sub(&mut a31, &b31, 1);
    assert_eq!(i31_to_bytes(&a31, n), hexb(ahex), "sub undoes add (i31)");
}

#[test]
fn mulacc_product() {
    // d = a*b for two multi-word values; compare i31 and i32 results.
    let ahex = "0000000123456789abcdef00";
    let bhex = "000000000fedcba987654321";
    let bits_a = ahex.len() * 4;
    let bits_b = bhex.len() * 4;
    let na = ahex.len() / 2;
    let nb = bhex.len() / 2;

    // i31
    let mut a = i31_alloc(bits_a);
    br_i31_decode(&mut a, &hexb(ahex), na);
    let mut b = i31_alloc(bits_b);
    br_i31_decode(&mut b, &hexb(bhex), nb);
    let mut d = vec![0u32; 4 + (bits_a + bits_b) / 31 + 4];
    // d announced bit length must initially match a's (per the contract).
    d[0] = a[0];
    br_i31_mulacc(&mut d, &a, &b);
    let r31 = i31_to_bytes(&d, na + nb);

    // i32
    let mut a2 = i32_alloc(bits_a);
    br_i32_decode(&mut a2, &hexb(ahex), na);
    let mut b2 = i32_alloc(bits_b);
    br_i32_decode(&mut b2, &hexb(bhex), nb);
    let mut d2 = vec![0u32; 4 + (bits_a + bits_b) / 32 + 4];
    d2[0] = a2[0];
    br_i32_mulacc(&mut d2, &a2, &b2);
    let r32 = i32_to_bytes(&d2, na + nb);

    assert_eq!(r31, r32, "mulacc i31 vs i32");

    // Independently computed product (fits well within u128).
    let av = u128::from_str_radix("123456789abcdef00", 16).unwrap();
    let bv = u128::from_str_radix("fedcba987654321", 16).unwrap();
    let prod = av * bv;
    let len = na + nb;
    let mut exp = vec![0u8; len];
    let pb = prod.to_be_bytes(); // 16 bytes, big-endian
    exp[len - 16..].copy_from_slice(&pb);
    assert_eq!(r31, exp, "mulacc value");
}

// ---- iszero / bit_length / ninv ---------------------------------------------

#[test]
fn iszero_and_ninv() {
    let mhex = "c0decafe00112233445566778899aabbccddeeff0123456789abcdef13371337";
    let m31 = make_mod31(mhex);
    assert_eq!(br_i31_iszero(&m31), 0);

    let mut z = i31_alloc(256);
    z[0] = m31[0];
    assert_eq!(br_i31_iszero(&z), 1);

    // -(1/m0) mod 2^31 : check m0 * m0i == -1 mod 2^31.
    let m0 = m31[1];
    let m0i = br_i31_ninv31(m0);
    assert_eq!(m0.wrapping_mul(m0i) & 0x7FFFFFFF, 0x7FFFFFFF & (-1i32 as u32));
    // even input -> 0
    assert_eq!(br_i31_ninv31(4), 0);

    // i32 ninv: m0 * m0i == -1 mod 2^32
    let m32 = make_mod32(mhex);
    let m0_32 = m32[1];
    let m0i_32 = br_i32_ninv32(m0_32);
    assert_eq!(m0_32.wrapping_mul(m0i_32), 0xFFFFFFFF);
}

// ---- br_divrem --------------------------------------------------------------

#[test]
fn divrem_known() {
    // (hi:lo) / d ; hi < d required.
    let cases: [(u32, u32, u32); 5] = [
        (0, 100, 7),
        (1, 0, 3),                       // 2^32 / 3
        (0x12345678, 0x9ABCDEF0, 0xFEDCBA98),
        (0, 0xFFFFFFFF, 2),
        (0x7FFFFFFF, 0xFFFFFFFF, 0x80000000),
    ];
    for (hi, lo, d) in cases {
        let dividend = ((hi as u64) << 32) | lo as u64;
        let q_exp = (dividend / d as u64) as u32;
        let r_exp = (dividend % d as u64) as u32;
        let mut r = 0u32;
        let q = br_divrem(hi, lo, d, &mut r);
        assert_eq!(q, q_exp, "divrem quotient for {hi:#x}:{lo:#x}/{d:#x}");
        assert_eq!(r, r_exp, "divrem remainder for {hi:#x}:{lo:#x}/{d:#x}");
        assert_eq!(br_rem(hi, lo, d), r_exp);
        assert_eq!(br_div(hi, lo, d), q_exp);
    }
}
