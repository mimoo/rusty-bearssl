/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Convert an ECDSA signature from "raw" to "asn1" (`src/ec/ecdsa_rta.c`).

/*
 * Compute the ASN.1 encoded length for the provided integer. The ASN.1
 * encoding is signed, so its leading bit must have value 0; it must also be
 * minimal.
 */
fn asn1_int_length(x: &[u8]) -> usize {
    let mut start = 0;
    let mut xlen = x.len();
    while xlen > 0 && x[start] == 0 {
        start += 1;
        xlen -= 1;
    }
    if xlen == 0 || x[start] >= 0x80 {
        xlen += 1;
    }
    xlen
}

/// see bearssl_ec.h
///
/// Conversion is done in place; the new length is returned (0 on error).
/// Conversion may enlarge the signature by no more than 9 bytes.
pub fn br_ecdsa_raw_to_asn1(sig: &mut [u8], sig_len: usize) -> usize {
    let mut tmp = [0u8; 257];

    if (sig_len & 1) != 0 {
        return 0;
    }

    /*
     * Compute lengths for the two integers.
     */
    let hlen = sig_len >> 1;
    let rlen = asn1_int_length(&sig[..hlen]);
    let slen = asn1_int_length(&sig[hlen..hlen + hlen]);
    if rlen > 125 || slen > 125 {
        return 0;
    }

    /*
     * SEQUENCE header.
     */
    tmp[0] = 0x30;
    let zlen = rlen + slen + 4;
    let mut off;
    if zlen >= 0x80 {
        tmp[1] = 0x81;
        tmp[2] = zlen as u8;
        off = 3;
    } else {
        tmp[1] = zlen as u8;
        off = 2;
    }

    /*
     * First INTEGER (r).
     */
    tmp[off] = 0x02;
    off += 1;
    tmp[off] = rlen as u8;
    off += 1;
    if rlen > hlen {
        tmp[off] = 0x00;
        tmp[off + 1..off + 1 + hlen].copy_from_slice(&sig[..hlen]);
    } else {
        tmp[off..off + rlen].copy_from_slice(&sig[hlen - rlen..hlen]);
    }
    off += rlen;

    /*
     * Second INTEGER (s).
     */
    tmp[off] = 0x02;
    off += 1;
    tmp[off] = slen as u8;
    off += 1;
    if slen > hlen {
        tmp[off] = 0x00;
        tmp[off + 1..off + 1 + hlen].copy_from_slice(&sig[hlen..hlen + hlen]);
    } else {
        tmp[off..off + slen].copy_from_slice(&sig[sig_len - slen..sig_len]);
    }
    off += slen;

    /*
     * Return ASN.1 signature.
     */
    sig[..off].copy_from_slice(&tmp[..off]);
    off
}
