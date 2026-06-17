//! Known-answer tests for the EC module, using the official BearSSL test
//! vectors (from test/test_crypto.c) and RFC 7748 / RFC 6979.

use bearssl::ec::*;
use bearssl::hash::{
    br_hash_class, br_sha1_vtable, br_sha224_vtable, br_sha256_vtable, br_sha384_vtable,
    br_sha512_vtable, BR_HASHDESC_OUT_MASK, BR_HASHDESC_OUT_OFF,
};

fn hb(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn hash_msg(hf: &'static br_hash_class, msg: &[u8]) -> Vec<u8> {
    let mut cc = (hf.new)();
    cc.update(msg);
    let len = ((hf.desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK) as usize;
    let mut out = vec![0u8; len];
    cc.out(&mut out);
    out
}

// --- KAT scalar multiplication: k*G must equal the published point. ----------

fn ec_kat_inner(sk: &str, su: &str, imp: &br_ec_impl, curve: i32) {
    let bk = hb(sk);
    let eu = hb(su);
    let g = (imp.generator)(curve);
    assert_eq!(eu.len(), g.len(), "KAT vector length mismatch");

    let mut eg = g.to_vec();
    assert_eq!((imp.mul)(&mut eg, &bk, curve), 1, "mul failed");
    assert_eq!(eg, eu, "mul KAT mismatch");

    // mulgen must yield the same point for the same scalar.
    let mut r = vec![0u8; g.len()];
    let rlen = (imp.mulgen)(&mut r, &bk, curve);
    assert_eq!(rlen, g.len());
    assert_eq!(r, eu, "mulgen KAT mismatch");
}

#[test]
fn p256_kat_prime_i31() {
    ec_kat_inner(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        &br_ec_prime_i31,
        BR_EC_secp256r1,
    );
}

#[test]
fn p256_kat_p256_m31() {
    ec_kat_inner(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        &br_ec_p256_m31,
        BR_EC_secp256r1,
    );
}

#[test]
fn p384_kat_prime_i31() {
    ec_kat_inner(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        &br_ec_prime_i31,
        BR_EC_secp384r1,
    );
}

#[test]
fn p521_kat_prime_i31() {
    ec_kat_inner(
        "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        "0401894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A400493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
        &br_ec_prime_i31,
        BR_EC_secp521r1,
    );
}

// --- P-256 carry KATs (mul by 0x10), prime_i31 and p256_m31 agree. ----------

fn p256_carry(imp: &br_ec_impl, sp: &str, sq: &str) {
    let mut p = hb(sp);
    let q = hb(sq);
    let k = [0x10u8];
    assert_eq!((imp.mul)(&mut p, &k, BR_EC_secp256r1), 1);
    assert_eq!(p, q, "P256 carry KAT mismatch");
}

#[test]
fn p256_carry_kats() {
    for imp in [&br_ec_prime_i31, &br_ec_p256_m31] {
        p256_carry(
            imp,
            "0435BAA24B2B6E1B3C88E22A383BD88CC4B9A3166E7BCF94FF6591663AE066B33B821EBA1B4FC8EA609A87EB9A9C9A1CCD5C9F42FA1365306F64D7CAA718B8C978",
            "0447752A76CA890328D34E675C4971EC629132D1FC4863EDB61219B72C4E58DC5E9D51E7B293488CFD913C3CF20E438BB65C2BA66A7D09EABB45B55E804260C5EB",
        );
        p256_carry(
            imp,
            "04DCAE9D9CE211223602024A6933BD42F77B6BF4EAB9C8915F058C149419FADD2CC9FC0707B270A1B5362BA4D249AFC8AC3DA1EFCA8270176EEACA525B49EE19E6",
            "048DAC7B0BE9B3206FCE8B24B6B4AEB122F2A67D13E536B390B6585CA193427E63F222388B5F51D744D6F5D47536D89EEEC89552BCB269E7828019C4410DFE980A",
        );
    }
}

// --- prime_i31 and p256_m31 must agree on a generic scalar multiplication. ---

#[test]
fn p256_prime_vs_m31_agree() {
    let g = br_ec_prime_i31.generator;
    let base = (g)(BR_EC_secp256r1).to_vec();
    // A few arbitrary scalars (< n).
    let scalars = [
        "0000000000000000000000000000000000000000000000000000000000000002",
        "1122334455667788990011223344556677889900112233445566778899001122",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    ];
    for s in scalars {
        let k = hb(s);
        let mut a = base.clone();
        let mut b = base.clone();
        let r1 = (br_ec_prime_i31.mul)(&mut a, &k, BR_EC_secp256r1);
        let r2 = (br_ec_p256_m31.mul)(&mut b, &k, BR_EC_secp256r1);
        assert_eq!(r1, r2);
        assert_eq!(a, b, "prime_i31 vs p256_m31 mul disagree for {s}");

        // mulgen too.
        let mut ga = vec![0u8; base.len()];
        let mut gb = vec![0u8; base.len()];
        (br_ec_prime_i31.mulgen)(&mut ga, &k, BR_EC_secp256r1);
        (br_ec_p256_m31.mulgen)(&mut gb, &k, BR_EC_secp256r1);
        assert_eq!(ga, gb, "prime_i31 vs p256_m31 mulgen disagree");
        assert_eq!(ga, a, "mulgen vs mul on generator disagree");
    }
}

// --- X25519, RFC 7748 section 5.2 single-iteration vectors. ------------------

fn revbytes(b: &mut [u8]) {
    b.reverse();
}

fn x25519_one(scalar_le: &str, u_in: &str, u_out: &str) {
    let mut bk = [0u8; 32];
    bk.copy_from_slice(&hb(scalar_le));
    revbytes(&mut bk); // KAT scalar given little-endian; mul wants big-endian
    let mut bu = [0u8; 32];
    bu.copy_from_slice(&hb(u_in));
    let br = hb(u_out);
    assert_eq!(
        (br_ec_c25519_i31.mul)(&mut bu, &bk, BR_EC_curve25519),
        1,
        "X25519 mul failed"
    );
    assert_eq!(&bu[..], &br[..], "X25519 KAT mismatch");
}

#[test]
fn x25519_rfc7748() {
    x25519_one(
        "A546E36BF0527C9D3B16154B82465EDD62144C0AC1FC5A18506A2244BA449AC4",
        "E6DB6867583030DB3594C1A424B15F7C726624EC26B3353B10A903A6D0AB1C4C",
        "C3DA55379DE9C6908E94EA4DF28D084F32ECCF03491C71F754B4075577A28552",
    );
    x25519_one(
        "4B66E9D4D1B4673C5AD22691957D6AF5C11B6421E0EA01D42CA4169E7918BA0D",
        "E5210F12786811D3F4B7959D0538AE2C31DBE7106FC03C3EFC4CD549C715A493",
        "95CBDE9476E8907D7AADE45CB4B873F88B595A68799FA152E6F8F7647AAC7957",
    );
}

// --- X25519 iterated KAT (RFC 7748 section 5.2): 1 and 1000 iterations. ------

#[test]
fn x25519_iterated() {
    let mut bu = [0u8; 32];
    bu[0] = 0x09;
    let mut bk = bu;
    for i in 1..=1000 {
        revbytes(&mut bk);
        assert_eq!((br_ec_c25519_i31.mul)(&mut bu, &bk, BR_EC_curve25519), 1);
        revbytes(&mut bk);
        // swap bu and bk
        std::mem::swap(&mut bu, &mut bk);
        if i == 1 {
            assert_eq!(
                hex::encode_upper(bk),
                "422C8E7A6227D7BCA1350B3E2BB7279F7897B87BB6854B783C60E80311AE3079"
            );
        }
        if i == 1000 {
            assert_eq!(
                hex::encode_upper(bk),
                "684CF59BA83309552800EF566F2F4D3C1C3887C49360E3875F2EB94D99532C51"
            );
        }
    }
}

// --- muladd cross-check: x*A + y*B == z*G where z = a*x + b*y mod n. ---------
// (Mirrors test_EC_inner's basic case, with fixed scalars to stay deterministic.)

#[test]
fn p256_muladd_consistency() {
    // Use the same scalar both ways via mulgen, exercising x*G + y*G = (x+y)*G,
    // which both prime_i31 and p256_m31 must compute consistently.
    let g = (br_ec_prime_i31.generator)(BR_EC_secp256r1);
    let x = hb("0000000000000000000000000000000000000000000000000000000000000003");
    let y = hb("0000000000000000000000000000000000000000000000000000000000000005");
    // z = 8
    let z = hb("0000000000000000000000000000000000000000000000000000000000000008");

    for imp in [&br_ec_prime_i31, &br_ec_p256_m31] {
        let mut a = g.to_vec();
        // A = 1*G = G; B = NULL -> generator.
        let mut ea = g.to_vec();
        (imp.mul)(&mut ea, &[1], BR_EC_secp256r1);
        let r = (imp.muladd)(&mut ea, None, &x, &y, BR_EC_secp256r1);
        assert_eq!(r, 1, "muladd failed");

        let mut ez = g.to_vec();
        (imp.mul)(&mut ez, &z, BR_EC_secp256r1);
        assert_eq!(ea, ez, "muladd != (x+y)*G");
        let _ = &mut a;
    }
}

// --- ECDSA: KAT verify and sign round-trip (RFC 6979 vectors). ---------------

struct EcdsaKat {
    hf: &'static br_hash_class,
    msg: &'static str,
    sraw: &'static str,
    sasn1: &'static str,
}

static EC_P256_PUB_POINT: [u8; 65] = [
    0x04, 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D,
    0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F,
    0xB6, 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC,
    0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22,
    0x99,
];

static EC_P256_PRIV_X: [u8; 32] = [
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
];

fn p256_ecdsa_kats() -> Vec<EcdsaKat> {
    vec![
        EcdsaKat {
            hf: &br_sha1_vtable,
            msg: "sample",
            sraw: "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D326D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB",
            sasn1: "3044022061340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D3202206D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB",
        },
        EcdsaKat {
            hf: &br_sha224_vtable,
            msg: "sample",
            sraw: "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3FB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",
            sasn1: "3045022053B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F022100B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",
        },
        EcdsaKat {
            hf: &br_sha256_vtable,
            msg: "sample",
            sraw: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
            sasn1: "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        },
        EcdsaKat {
            hf: &br_sha384_vtable,
            msg: "sample",
            sraw: "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF77194861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
            sasn1: "304402200EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF771902204861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
        },
        EcdsaKat {
            hf: &br_sha512_vtable,
            msg: "sample",
            sraw: "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F002362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
            sasn1: "30450221008496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F0002202362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
        },
        EcdsaKat {
            hf: &br_sha256_vtable,
            msg: "test",
            sraw: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
            sasn1: "3045022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D383670220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
        },
    ]
}

#[test]
fn ecdsa_p256_kat_raw_and_asn1() {
    let pk = br_ec_public_key {
        curve: BR_EC_secp256r1,
        q: &EC_P256_PUB_POINT,
    };
    let sk = br_ec_private_key {
        curve: BR_EC_secp256r1,
        x: &EC_P256_PRIV_X,
    };

    for imp in [&br_ec_prime_i31, &br_ec_p256_m31] {
        for kv in p256_ecdsa_kats() {
            let hash = hash_msg(kv.hf, kv.msg.as_bytes());

            // --- raw form ---
            let sig = hb(kv.sraw);
            assert_eq!(
                br_ecdsa_i31_vrfy_raw(imp, &hash, &pk, &sig),
                1,
                "raw verify failed"
            );
            // Tamper the hash -> must fail.
            let mut bad = hash.clone();
            bad[0] ^= 0x80;
            assert_eq!(br_ecdsa_i31_vrfy_raw(imp, &bad, &pk, &sig), 0);

            // Sign and compare to the KAT (RFC 6979 is deterministic).
            let mut out = [0u8; 150];
            let n = br_ecdsa_i31_sign_raw(imp, kv.hf, &hash, &sk, &mut out);
            assert_eq!(&out[..n], &sig[..], "raw sign mismatch");

            // --- asn1 form ---
            let asn1 = hb(kv.sasn1);
            assert_eq!(
                br_ecdsa_i31_vrfy_asn1(imp, &hash, &pk, &asn1),
                1,
                "asn1 verify failed"
            );
            let mut out2 = [0u8; 150];
            let n2 = br_ecdsa_i31_sign_asn1(imp, kv.hf, &hash, &sk, &mut out2);
            assert_eq!(&out2[..n2], &asn1[..], "asn1 sign mismatch");
        }
    }
}

// --- ASN.1 <-> raw conversion round-trip. ------------------------------------

#[test]
fn ecdsa_atr_rta_roundtrip() {
    for kv in p256_ecdsa_kats() {
        let raw = hb(kv.sraw);
        let asn1 = hb(kv.sasn1);

        // raw -> asn1
        let mut buf = [0u8; 150];
        buf[..raw.len()].copy_from_slice(&raw);
        let n = br_ecdsa_raw_to_asn1(&mut buf, raw.len());
        assert_eq!(&buf[..n], &asn1[..], "raw_to_asn1 mismatch");

        // asn1 -> raw  (note: raw form may drop a leading zero pair, so we
        // re-encode to asn1 and compare that, matching BearSSL's contract).
        let mut buf2 = [0u8; 150];
        buf2[..asn1.len()].copy_from_slice(&asn1);
        let m = br_ecdsa_asn1_to_raw(&mut buf2, asn1.len());
        let mut buf3 = buf2;
        let k = br_ecdsa_raw_to_asn1(&mut buf3, m);
        assert_eq!(&buf3[..k], &asn1[..], "asn1->raw->asn1 mismatch");
    }
}

// --- compute_pub: derive the public key from the private key. ----------------

#[test]
fn compute_pub_p256() {
    let sk = br_ec_private_key {
        curve: BR_EC_secp256r1,
        x: &EC_P256_PRIV_X,
    };
    for imp in [&br_ec_prime_i31, &br_ec_p256_m31] {
        let mut kbuf = [0u8; BR_EC_KBUF_PUB_MAX_SIZE];
        let n = br_ec_compute_pub(imp, Some(&mut kbuf), &sk);
        assert_eq!(n, 65);
        assert_eq!(&kbuf[..65], &EC_P256_PUB_POINT[..], "computed pub mismatch");
    }
}
