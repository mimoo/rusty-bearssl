/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Shared T0 virtual-machine primitives.
//!
//! BearSSL's `x509_decoder.c`, `skey_decoder.c` and `x509_minimal.c` are all
//! emitted by the same "T0" compiler. Each embeds an identical helper prologue
//! (`t0_parse7E_unsigned`, `t0_parse7E_signed`, the `T0_VBYTE`/`T0_FBYTE`/
//! `T0_INT*` byte-encoding macros) and an identical threaded interpreter loop;
//! only the opcode table, code block and data block differ. This module hosts
//! the parts that are byte-for-byte identical across the three engines.
//!
//! ## Memory model
//!
//! The C interpreter addresses context fields by their `offsetof` value: opcodes
//! such as `set8`/`get32`/`read-blob-inner` compute `(unsigned char *)CTX +
//! addr`. Rust cannot reproduce that raw pointer arithmetic safely, so each
//! ported engine assigns its *own* stable offset constants to its addressable
//! fields and bakes those same constants into its code block via the [`T0_INT2`]
//! helper (exactly as the C source bakes `offsetof(...)`). The engine then
//! routes every byte-addressed access through a small accessor that matches on
//! the offset constant. Because the code block and the accessor use the same
//! mapping, behaviour is identical to C.

// ---- 7E variable-length integer decoding (verbatim from the generated code) -

/// Decode an unsigned 7-bit-chunked integer, advancing `ip`.
/// Mirrors `t0_parse7E_unsigned`.
#[inline]
pub fn t0_parse7E_unsigned(code: &[u8], ip: &mut usize) -> u32 {
    let mut x: u32 = 0;
    loop {
        let y = code[*ip];
        *ip += 1;
        x = (x << 7) | (y & 0x7F) as u32;
        if y < 0x80 {
            return x;
        }
    }
}

/// Decode a signed 7-bit-chunked integer, advancing `ip`.
/// Mirrors `t0_parse7E_signed`.
#[inline]
pub fn t0_parse7E_signed(code: &[u8], ip: &mut usize) -> i32 {
    let neg = ((code[*ip] >> 6) & 1) as u32;
    let mut x: u32 = 0u32.wrapping_sub(neg);
    loop {
        let y = code[*ip];
        *ip += 1;
        x = (x << 7) | (y & 0x7F) as u32;
        if y < 0x80 {
            if neg != 0 {
                return (!x as i32).wrapping_neg().wrapping_sub(1);
            } else {
                return x as i32;
            }
        }
    }
}

// ---- T0 code-block byte encoders (the T0_VBYTE/T0_FBYTE/T0_INT* macros) ------

#[inline]
pub const fn T0_VBYTE(x: u32, n: u32) -> u8 {
    (((x >> n) & 0x7F) | 0x80) as u8
}
#[inline]
pub const fn T0_FBYTE(x: u32, n: u32) -> u8 {
    ((x >> n) & 0x7F) as u8
}
#[inline]
pub const fn T0_SBYTE(x: u32) -> u8 {
    (((x >> 28).wrapping_add(0xF8)) ^ 0xF8) as u8
}

/// Single-byte literal (`T0_INT1`).
#[inline]
pub const fn T0_INT1(x: u32) -> [u8; 1] {
    [T0_FBYTE(x, 0)]
}
/// Two-byte literal (`T0_INT2`).
#[inline]
pub const fn T0_INT2(x: u32) -> [u8; 2] {
    [T0_VBYTE(x, 7), T0_FBYTE(x, 0)]
}

// ---- X.509 error codes (inc/bearssl_x509.h) ---------------------------------

pub const BR_ERR_X509_OK: i32 = 32;
pub const BR_ERR_X509_INVALID_VALUE: i32 = 33;
pub const BR_ERR_X509_TRUNCATED: i32 = 34;
pub const BR_ERR_X509_EMPTY_CHAIN: i32 = 35;
pub const BR_ERR_X509_INNER_TRUNC: i32 = 36;
pub const BR_ERR_X509_BAD_TAG_CLASS: i32 = 37;
pub const BR_ERR_X509_BAD_TAG_VALUE: i32 = 38;
pub const BR_ERR_X509_INDEFINITE_LENGTH: i32 = 39;
pub const BR_ERR_X509_EXTRA_ELEMENT: i32 = 40;
pub const BR_ERR_X509_UNEXPECTED: i32 = 41;
pub const BR_ERR_X509_NOT_CONSTRUCTED: i32 = 42;
pub const BR_ERR_X509_NOT_PRIMITIVE: i32 = 43;
pub const BR_ERR_X509_PARTIAL_BYTE: i32 = 44;
pub const BR_ERR_X509_BAD_BOOLEAN: i32 = 45;
pub const BR_ERR_X509_OVERFLOW: i32 = 46;
pub const BR_ERR_X509_BAD_DN: i32 = 47;
pub const BR_ERR_X509_BAD_TIME: i32 = 48;
pub const BR_ERR_X509_UNSUPPORTED: i32 = 49;
pub const BR_ERR_X509_LIMIT_EXCEEDED: i32 = 50;
pub const BR_ERR_X509_WRONG_KEY_TYPE: i32 = 51;
pub const BR_ERR_X509_BAD_SIGNATURE: i32 = 52;
pub const BR_ERR_X509_TIME_UNKNOWN: i32 = 53;
pub const BR_ERR_X509_EXPIRED: i32 = 54;
pub const BR_ERR_X509_DN_MISMATCH: i32 = 55;
pub const BR_ERR_X509_BAD_SERVER_NAME: i32 = 56;
pub const BR_ERR_X509_CRITICAL_EXTENSION: i32 = 57;
pub const BR_ERR_X509_NOT_CA: i32 = 58;
pub const BR_ERR_X509_FORBIDDEN_KEY_USAGE: i32 = 59;
pub const BR_ERR_X509_WEAK_PUBLIC_KEY: i32 = 60;
pub const BR_ERR_X509_NOT_TRUSTED: i32 = 62;

// ---- key types (inc/bearssl_x509.h) -----------------------------------------

pub const BR_KEYTYPE_RSA: u8 = 1;
pub const BR_KEYTYPE_EC: u8 = 2;
pub const BR_KEYTYPE_KEYX: u8 = 0x10;
pub const BR_KEYTYPE_SIGN: u8 = 0x20;

/// Buffer size to hold a decoded public key (`BR_X509_BUFSIZE_KEY`).
pub const BR_X509_BUFSIZE_KEY: usize = 520;
/// Buffer size to hold a certificate signature (`BR_X509_BUFSIZE_SIG`).
pub const BR_X509_BUFSIZE_SIG: usize = 512;
