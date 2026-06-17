use bearssl::codec::*;
use bearssl::inner::*;

#[test]
fn ct_primitives() {
    assert_eq!(MUX(1, 7, 9), 7);
    assert_eq!(MUX(0, 7, 9), 9);
    assert_eq!(EQ(5, 5), 1);
    assert_eq!(EQ(5, 6), 0);
    assert_eq!(NEQ(5, 6), 1);
    assert_eq!(GT(6, 5), 1);
    assert_eq!(GT(5, 6), 0);
    assert_eq!(GE(5, 5), 1);
    assert_eq!(LT(5, 6), 1);
    assert_eq!(LE(5, 5), 1);
    assert_eq!(CMP(5, 6), -1);
    assert_eq!(CMP(6, 5), 1);
    assert_eq!(CMP(5, 5), 0);
    assert_eq!(EQ0(0), 1);
    assert_eq!(GT0(3), 1);
    assert_eq!(LT0(-3), 1);
    assert_eq!(BIT_LENGTH(0), 0);
    assert_eq!(BIT_LENGTH(1), 1);
    assert_eq!(BIT_LENGTH(0xFFFFFFFF), 32);
    assert_eq!(MIN(3, 9), 3);
    assert_eq!(MAX(3, 9), 9);
}

#[test]
fn codec_roundtrip() {
    let mut buf = [0u8; 16];
    br_enc32be(&mut buf, 0x01020304);
    assert_eq!(&buf[..4], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(br_dec32be(&buf), 0x01020304);

    br_enc32le(&mut buf, 0x01020304);
    assert_eq!(&buf[..4], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(br_dec32le(&buf), 0x01020304);

    let vals = [0x1111u32, 0x2222, 0x3333];
    br_range_enc32be(&mut buf, &vals, 3);
    let mut out = [0u32; 3];
    br_range_dec32be(&mut out, 3, &buf);
    assert_eq!(out, vals);
}

#[test]
fn ccopy_conditional() {
    let mut dst = [1u8, 2, 3, 4];
    let src = [9u8, 9, 9, 9];
    br_ccopy(0, &mut dst, &src, 4);
    assert_eq!(dst, [1, 2, 3, 4]);
    br_ccopy(1, &mut dst, &src, 4);
    assert_eq!(dst, [9, 9, 9, 9]);
}
