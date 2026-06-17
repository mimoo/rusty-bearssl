//! TLS PRF known-answer test. Uses the canonical IETF TLS 1.2 SHA-256 PRF
//! test vector (widely published on the TLS WG mailing list).

use bearssl::ssl::{br_tls12_sha256_prf, br_tls_prf_seed_chunk};

fn hx(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn tls12_sha256_prf_kat() {
    let secret = hx("9bbe436ba940f017b17652849a71db35");
    let seed = hx("a0ba9f936cda311827a6f796ffd5198c");
    let expected = "e3f229ba727be17b8d122620557cd453\
                    c2aab21d07c3d495329b52d4e61edb5a\
                    6b301791e90d35c9c9a46b4e14baf9af\
                    0fa022f7077def17abfd3797c0564bab\
                    4fbc91666e9def9b97fce34f796789ba\
                    a48082d122ee42c5a72e5a5110fff701\
                    87347b66";
    let mut out = [0u8; 100];
    let chunks = [br_tls_prf_seed_chunk { data: &seed }];
    br_tls12_sha256_prf(&mut out, &secret, b"test label", &chunks);
    assert_eq!(hex::encode(out), expected.replace(char::is_whitespace, ""));
}

#[test]
fn prf_multi_seed_chunk_concatenation() {
    // Splitting the seed across chunks must equal a single concatenated seed.
    let secret = hx("9bbe436ba940f017b17652849a71db35");
    let seed = hx("a0ba9f936cda311827a6f796ffd5198c");
    let mut one = [0u8; 48];
    br_tls12_sha256_prf(&mut one, &secret, b"test label", &[br_tls_prf_seed_chunk { data: &seed }]);
    let mut split = [0u8; 48];
    br_tls12_sha256_prf(
        &mut split,
        &secret,
        b"test label",
        &[
            br_tls_prf_seed_chunk { data: &seed[..5] },
            br_tls_prf_seed_chunk { data: &seed[5..] },
        ],
    );
    assert_eq!(one, split);
}
