//! Known-answer tests for the hash module, using standard test vectors
//! (same vectors as BearSSL's test/test_crypto.c).

use bearssl::hash::*;

fn md5(data: &[u8]) -> Vec<u8> {
    let mut cc = (br_md5_vtable.new)();
    cc.update(data);
    let mut out = vec![0u8; br_md5_SIZE];
    cc.out(&mut out);
    out
}
fn sha1(data: &[u8]) -> Vec<u8> {
    let mut cc = (br_sha1_vtable.new)();
    cc.update(data);
    let mut out = vec![0u8; br_sha1_SIZE];
    cc.out(&mut out);
    out
}
fn run(vt: &'static br_hash_class, size: usize, data: &[u8]) -> Vec<u8> {
    let mut cc = (vt.new)();
    cc.update(data);
    let mut out = vec![0u8; size];
    cc.out(&mut out);
    out
}

#[test]
fn md5_kat() {
    assert_eq!(hex::encode(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex::encode(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex::encode(md5(b"The quick brown fox jumps over the lazy dog")),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
}

#[test]
fn sha1_kat() {
    assert_eq!(hex::encode(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex::encode(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        hex::encode(sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

#[test]
fn sha224_kat() {
    assert_eq!(
        hex::encode(run(&br_sha224_vtable, br_sha224_SIZE, b"abc")),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    );
    assert_eq!(
        hex::encode(run(&br_sha224_vtable, br_sha224_SIZE, b"")),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
}

#[test]
fn sha256_kat() {
    assert_eq!(
        hex::encode(run(&br_sha256_vtable, br_sha256_SIZE, b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(run(&br_sha256_vtable, br_sha256_SIZE, b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex::encode(run(
            &br_sha256_vtable,
            br_sha256_SIZE,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha384_kat() {
    assert_eq!(
        hex::encode(run(&br_sha384_vtable, br_sha384_SIZE, b"abc")),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
}

#[test]
fn sha512_kat() {
    assert_eq!(
        hex::encode(run(&br_sha512_vtable, br_sha512_SIZE, b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}

#[test]
fn long_message_multiblock() {
    // One million 'a' characters; classic SHA test vector.
    let data = vec![b'a'; 1_000_000];
    assert_eq!(
        hex::encode(run(&br_sha256_vtable, br_sha256_SIZE, &data)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    assert_eq!(
        hex::encode(sha1(&data)),
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    );
}

#[test]
fn incremental_update_matches() {
    // Splitting the input across update() calls must match a single call.
    let full = run(&br_sha256_vtable, br_sha256_SIZE, b"abcdefghijklmnopqrstuvwxyz");
    let mut cc = (br_sha256_vtable.new)();
    cc.update(b"abcde");
    cc.update(b"fghijklmno");
    cc.update(b"pqrstuvwxyz");
    let mut out = vec![0u8; br_sha256_SIZE];
    cc.out(&mut out);
    assert_eq!(out, full);
}

#[test]
fn clone_snapshots_state() {
    // Cloning a running context must capture an independent snapshot.
    let mut cc = (br_sha256_vtable.new)();
    cc.update(b"abc");
    let snapshot = cc.clone();
    cc.update(b"def");
    let mut a = vec![0u8; br_sha256_SIZE];
    let mut b = vec![0u8; br_sha256_SIZE];
    snapshot.out(&mut a);
    cc.out(&mut b);
    assert_eq!(hex::encode(&a), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex::encode(&b),
        hex::encode(run(&br_sha256_vtable, br_sha256_SIZE, b"abcdef"))
    );
}
