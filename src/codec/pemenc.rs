/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! PEM encoder (`src/codec/pemenc.c`).
//!
//! Wraps a binary object into a PEM text block (`-----BEGIN <banner>-----`,
//! Base64 body, `-----END <banner>-----`). Faithful port of `br_pem_encode`.

/// PEM encoding flag: split lines at 64 characters (`BR_PEM_LINE64`).
pub const BR_PEM_LINE64: u32 = 0x0001;
/// PEM encoding flag: use CR+LF line endings (`BR_PEM_CRLF`).
pub const BR_PEM_CRLF: u32 = 0x0002;

/// Get the appropriate Base64 character for a numeric value in the 0..63 range.
/// This is constant-time. Mirrors `b64char`.
#[inline]
fn b64char(x: u32) -> u8 {
    // Values 0 to 25 map to 0x41..0x5A ('A' to 'Z')
    // Values 26 to 51 map to 0x61..0x7A ('a' to 'z')
    // Values 52 to 61 map to 0x30..0x39 ('0' to '9')
    // Value 62 maps to 0x2B ('+')
    // Value 63 maps to 0x2F ('/')
    let a = x.wrapping_sub(26);
    let b = x.wrapping_sub(52);
    let c = x.wrapping_sub(62);

    // Looking at bits 8..15 of values a, b and c:
    //
    //     x       a   b   c
    //  ---------------------
    //   0..25    FF  FF  FF
    //   26..51   00  FF  FF
    //   52..61   00  00  FF
    //   62..63   00  00  00
    ((x.wrapping_add(0x41) & ((a & b & c) >> 8))
        | (x.wrapping_add(0x61 - 26) & ((!a & b & c) >> 8))
        | (x.wrapping_sub(52 - 0x30) & ((!a & !b & c) >> 8))
        | ((0x2B + ((x & 1) << 2)) & (!(a | b | c) >> 8))) as u8
}

/// see bearssl_pem.h (`br_pem_encode`).
///
/// If `dest` is `None`, the length of the encoded object (excluding the
/// terminating zero) is computed and returned without producing output.
/// Otherwise `dest` must be at least `br_pem_encode(None, ...) + 1` bytes; the
/// returned length excludes the final NUL, which is nevertheless written.
pub fn br_pem_encode(
    dest: Option<&mut [u8]>,
    data: &[u8],
    len: usize,
    banner: &str,
    flags: u32,
) -> usize {
    let banner = banner.as_bytes();
    let banner_len = banner.len();
    let lines = if (flags & BR_PEM_LINE64) != 0 {
        (len + 47) / 48
    } else {
        (len + 56) / 57
    };
    let mut dlen = (banner_len << 1) + 30 + (((len + 2) / 3) << 2) + lines + 2;
    if (flags & BR_PEM_CRLF) != 0 {
        dlen += lines + 2;
    }

    let d = match dest {
        None => return dlen,
        Some(d) => d,
    };

    // We always move the source data to the end of the output buffer; the
    // encoding process never "catches up" except at the very end. (In C this is
    // a memmove that also handles dest/data overlap; here `data` and `dest` are
    // distinct slices, so a copy suffices.)
    let buf_off = dlen - len;
    d[buf_off..buf_off + len].copy_from_slice(&data[..len]);

    let mut p = 0usize; // write cursor (mirrors `d` pointer advance)

    d[p..p + 11].copy_from_slice(b"-----BEGIN ");
    p += 11;
    d[p..p + banner_len].copy_from_slice(banner);
    p += banner_len;
    d[p..p + 5].copy_from_slice(b"-----");
    p += 5;
    if (flags & BR_PEM_CRLF) != 0 {
        d[p] = 0x0D;
        p += 1;
    }
    d[p] = 0x0A;
    p += 1;

    let mut off = 0;
    let lim = if (flags & BR_PEM_LINE64) != 0 { 16 } else { 19 };
    let mut u = 0usize;
    while u + 2 < len {
        let w = ((d[buf_off + u] as u32) << 16)
            | ((d[buf_off + u + 1] as u32) << 8)
            | (d[buf_off + u + 2] as u32);
        d[p] = b64char(w >> 18);
        p += 1;
        d[p] = b64char((w >> 12) & 0x3F);
        p += 1;
        d[p] = b64char((w >> 6) & 0x3F);
        p += 1;
        d[p] = b64char(w & 0x3F);
        p += 1;
        off += 1;
        if off == lim {
            off = 0;
            if (flags & BR_PEM_CRLF) != 0 {
                d[p] = 0x0D;
                p += 1;
            }
            d[p] = 0x0A;
            p += 1;
        }
        u += 3;
    }
    if u < len {
        let mut w = (d[buf_off + u] as u32) << 16;
        if u + 1 < len {
            w |= (d[buf_off + u + 1] as u32) << 8;
        }
        d[p] = b64char(w >> 18);
        p += 1;
        d[p] = b64char((w >> 12) & 0x3F);
        p += 1;
        if u + 1 < len {
            d[p] = b64char((w >> 6) & 0x3F);
            p += 1;
        } else {
            d[p] = 0x3D;
            p += 1;
        }
        d[p] = 0x3D;
        p += 1;
        off += 1;
    }
    if off != 0 {
        if (flags & BR_PEM_CRLF) != 0 {
            d[p] = 0x0D;
            p += 1;
        }
        d[p] = 0x0A;
        p += 1;
    }

    d[p..p + 9].copy_from_slice(b"-----END ");
    p += 9;
    d[p..p + banner_len].copy_from_slice(banner);
    p += banner_len;
    d[p..p + 5].copy_from_slice(b"-----");
    p += 5;
    if (flags & BR_PEM_CRLF) != 0 {
        d[p] = 0x0D;
        p += 1;
    }
    d[p] = 0x0A;
    p += 1;

    // Final zero, not counted in returned length.
    d[p] = 0x00;

    dlen
}
