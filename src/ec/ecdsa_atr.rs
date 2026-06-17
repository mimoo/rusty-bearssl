/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Convert an ECDSA signature from "asn1" to "raw" (`src/ec/ecdsa_atr.c`).

/// see bearssl_ec.h
///
/// Conversion is done in place; the new length is returned (0 on error). The
/// raw length is never more than twice the source length.
pub fn br_ecdsa_asn1_to_raw(sig: &mut [u8], mut sig_len: usize) -> usize {
    let mut tmp = [0u8; 254];

    if sig_len < 8 {
        return 0;
    }

    /* First byte is SEQUENCE tag. */
    if sig[0] != 0x30 {
        return 0;
    }

    /*
     * The SEQUENCE length is encoded over one or two bytes; total contents
     * limited to 255 bytes.
     */
    let mut zlen = sig[1] as usize;
    let mut off;
    if zlen > 0x80 {
        if zlen != 0x81 {
            return 0;
        }
        zlen = sig[2] as usize;
        if zlen != sig_len - 3 {
            return 0;
        }
        off = 3;
    } else {
        if zlen != sig_len - 2 {
            return 0;
        }
        off = 2;
    }

    /* First INTEGER (r). */
    if sig[off] != 0x02 {
        return 0;
    }
    off += 1;
    let rlen = sig[off] as usize;
    off += 1;
    if rlen >= 0x80 {
        return 0;
    }
    let r_off = off;
    off += rlen;

    /* Second INTEGER (s). */
    if off + 2 > sig_len {
        return 0;
    }
    if sig[off] != 0x02 {
        return 0;
    }
    off += 1;
    let slen = sig[off] as usize;
    off += 1;
    if slen >= 0x80 || slen != sig_len - off {
        return 0;
    }
    let s_off = off;

    /* Remove leading zeros from r and s. */
    let mut r_off = r_off;
    let mut rlen = rlen;
    while rlen > 0 && sig[r_off] == 0 {
        rlen -= 1;
        r_off += 1;
    }
    let mut s_off = s_off;
    let mut slen = slen;
    while slen > 0 && sig[s_off] == 0 {
        slen -= 1;
        s_off += 1;
    }

    /*
     * Compute common length for the two integers, copy into the temporary,
     * then back over the signature buffer.
     */
    zlen = if rlen > slen { rlen } else { slen };
    sig_len = zlen << 1;
    for b in tmp[..sig_len].iter_mut() {
        *b = 0;
    }
    tmp[zlen - rlen..zlen].copy_from_slice(&sig[r_off..r_off + rlen]);
    tmp[sig_len - slen..sig_len].copy_from_slice(&sig[s_off..s_off + slen]);
    sig[..sig_len].copy_from_slice(&tmp[..sig_len]);
    sig_len
}
