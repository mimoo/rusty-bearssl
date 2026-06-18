/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! ASN.1 DER encoding helpers (`src/x509/asn1enc.c`).
//!
//! Provides the building blocks used by the key-encoding functions:
//! preparation of unsigned big integers (`br_asn1_uint_prepare`), DER length
//! encoding (`br_asn1_encode_length`, aka `len_of_len`) and DER INTEGER
//! encoding (`br_asn1_encode_uint`).

/// Encoding information about an INTEGER value (`br_asn1_uint`).
///
/// `data`/`len` describe the source big-endian bytes (with leading zeros
/// removed); `asn1len` is the length of the encoded INTEGER value contents,
/// which is one greater than `len` when a leading 0x00 padding byte is needed
/// (i.e. when the high bit of the first byte is set, or the value is zero).
#[derive(Clone, Copy)]
pub struct br_asn1_uint<'a> {
    pub data: &'a [u8],
    pub len: usize,
    pub asn1len: usize,
}

/// see inner.h (`br_asn1_uint_prepare`).
pub fn br_asn1_uint_prepare(xdata: &[u8]) -> br_asn1_uint<'_> {
    let mut x = xdata;
    while !x.is_empty() && x[0] == 0 {
        x = &x[1..];
    }
    let len = x.len();
    let mut asn1len = len;
    if len == 0 || x[0] >= 0x80 {
        asn1len += 1;
    }
    br_asn1_uint { data: x, len, asn1len }
}

/// see inner.h (`br_asn1_encode_length`). With `dest = None` this is the
/// `len_of_len` macro: it returns the number of bytes the DER length encoding
/// of `len` occupies, without writing anything.
pub fn br_asn1_encode_length(dest: Option<&mut [u8]>, len: usize) -> usize {
    if len < 0x80 {
        if let Some(buf) = dest {
            buf[0] = len as u8;
        }
        return 1;
    }
    let mut i = 0;
    let mut z = len;
    while z != 0 {
        i += 1;
        z >>= 8;
    }
    if let Some(buf) = dest {
        buf[0] = (0x80 + i) as u8;
        let mut p = 1;
        let mut j = i as i32 - 1;
        while j >= 0 {
            buf[p] = (len >> ((j as usize) << 3)) as u8;
            p += 1;
            j -= 1;
        }
    }
    i + 1
}

/// `len_of_len(len)`: number of bytes used by the DER length encoding of `len`.
#[inline]
pub fn len_of_len(len: usize) -> usize {
    br_asn1_encode_length(None, len)
}

/// see inner.h (`br_asn1_encode_uint`).
pub fn br_asn1_encode_uint(dest: Option<&mut [u8]>, pp: br_asn1_uint) -> usize {
    let buf = match dest {
        None => return 1 + br_asn1_encode_length(None, pp.asn1len) + pp.asn1len,
        Some(buf) => buf,
    };
    buf[0] = 0x02;
    let lenlen = br_asn1_encode_length(Some(&mut buf[1..]), pp.asn1len);
    // buf += 1 + lenlen; then *buf = 0x00; memcpy(buf + asn1len - len, data, len)
    let base = 1 + lenlen;
    buf[base] = 0x00;
    let dst = base + pp.asn1len - pp.len;
    buf[dst..dst + pp.len].copy_from_slice(&pp.data[..pp.len]);
    1 + lenlen + pp.asn1len
}
