/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! `br_rsa_i31_keygen_inner` (mirrors `src/rsa/rsa_i31_keygen_inner.c`).

use super::br_rsa_private_key;
use super::{BR_MAX_RSA_SIZE, BR_MIN_RSA_SIZE};
use crate::inner::{br_enc32be, EQ0, GT, MUL31};
use crate::int::{
    br_i31_add, br_i31_decode_reduce, br_i31_encode, br_i31_moddiv, br_i31_mulacc, br_i31_ninv31,
    br_i31_rshift, br_i31_sub, br_i31_zero,
};
use crate::rand::PrngState;

/// Type of the i31 windowed modular exponentiation (`br_i31_modpow_opt_type`).
pub type br_i31_modpow_opt_type =
    fn(x: &mut [u32], e: &[u8], elen: usize, m: &[u32], m0i: u32, tmp: &mut [u32], twlen: usize) -> u32;

/// Byte layout of the generated key elements within the caller-supplied
/// buffers, returned by [`br_rsa_i31_keygen_inner`]. Lengths are in bytes; the
/// private elements lie consecutively in `kbuf_priv` (p, q, dp, dq, iq); the
/// public elements lie in `kbuf_pub` (n then e).
#[derive(Clone, Copy, Debug)]
pub struct KeygenOut {
    pub n_bitlen: u32,
    pub plen: usize,
    pub qlen: usize,
    pub dplen: usize,
    pub dqlen: usize,
    pub iqlen: usize,
    /// Public modulus length in bytes (in `kbuf_pub`), if a public key was made.
    pub nlen: usize,
    /// Public exponent length in bytes (in `kbuf_pub`, right after n).
    pub elen: usize,
}

const fn cmax(x: usize, y: usize) -> usize {
    if x > y {
        x
    } else {
        y
    }
}
const fn round2(x: usize) -> usize {
    ((x + 1) >> 1) << 1
}
const TEMPS: usize = cmax(512, round2(7 * ((((BR_MAX_RSA_SIZE + 1) >> 1) + 61) / 31)));

/// Big-endian unsigned representation of the product of all small primes from
/// 13 to 1481.
static SMALL_PRIMES: [u8; 256] = [
    0x2E, 0xAB, 0x92, 0xD1, 0x8B, 0x12, 0x47, 0x31, 0x54, 0x0A, 0x99, 0x5D, 0x25, 0x5E, 0xE2, 0x14,
    0x96, 0x29, 0x1E, 0xB7, 0x78, 0x70, 0xCC, 0x1F, 0xA5, 0xAB, 0x8D, 0x72, 0x11, 0x37, 0xFB, 0xD8,
    0x1E, 0x3F, 0x5B, 0x34, 0x30, 0x17, 0x8B, 0xE5, 0x26, 0x28, 0x23, 0xA1, 0x8A, 0xA4, 0x29, 0xEA,
    0xFD, 0x9E, 0x39, 0x60, 0x8A, 0xF3, 0xB5, 0xA6, 0xEB, 0x3F, 0x02, 0xB6, 0x16, 0xC3, 0x96, 0x9D,
    0x38, 0xB0, 0x7D, 0x82, 0x87, 0x0C, 0xF7, 0xBE, 0x24, 0xE5, 0x5F, 0x41, 0x04, 0x79, 0x76, 0x40,
    0xE7, 0x00, 0x22, 0x7E, 0xB5, 0x85, 0x7F, 0x8D, 0x01, 0x50, 0xE9, 0xD3, 0x29, 0x42, 0x08, 0xB3,
    0x51, 0x40, 0x7B, 0xD7, 0x8D, 0xCC, 0x10, 0x01, 0x64, 0x59, 0x28, 0xB6, 0x53, 0xF3, 0x50, 0x4E,
    0xB1, 0xF2, 0x58, 0xCD, 0x6E, 0xF5, 0x56, 0x3E, 0x66, 0x2F, 0xD7, 0x07, 0x7F, 0x52, 0x4C, 0x13,
    0x24, 0xDC, 0x8E, 0x8D, 0xCC, 0xED, 0x77, 0xC4, 0x21, 0xD2, 0xFD, 0x08, 0xEA, 0xD7, 0xC0, 0x5C,
    0x13, 0x82, 0x81, 0x31, 0x2F, 0x2B, 0x08, 0xE4, 0x80, 0x04, 0x7A, 0x0C, 0x8A, 0x3C, 0xDC, 0x22,
    0xE4, 0x5A, 0x7A, 0xB0, 0x12, 0x5E, 0x4A, 0x76, 0x94, 0x77, 0xC2, 0x0E, 0x92, 0xBA, 0x8A, 0xA0,
    0x1F, 0x14, 0x51, 0x1E, 0x66, 0x6C, 0x38, 0x03, 0x6C, 0xC7, 0x4A, 0x4B, 0x70, 0x80, 0xAF, 0xCA,
    0x84, 0x51, 0xD8, 0xD2, 0x26, 0x49, 0xF5, 0xA8, 0x5E, 0x35, 0x4B, 0xAC, 0xCE, 0x29, 0x92, 0x33,
    0xB7, 0xA2, 0x69, 0x7D, 0x0C, 0xE0, 0x9C, 0xDB, 0x04, 0xD6, 0xB4, 0xBC, 0x39, 0xD7, 0x7F, 0x9E,
    0x9D, 0x78, 0x38, 0x7F, 0x51, 0x54, 0x50, 0x8B, 0x9E, 0x9C, 0x03, 0x6C, 0xF5, 0x9D, 0x2C, 0x74,
    0x57, 0xF0, 0x27, 0x2A, 0xC3, 0x47, 0xCA, 0xB9, 0xD7, 0x5C, 0xFF, 0xC2, 0xAC, 0x65, 0x4E, 0xBD,
];

/// Make a random integer of the provided _encoded_ size into `x[1..]`. The
/// header word `x[0]` is untouched.
fn mkrand(rng: &mut dyn PrngState, x: &mut [u32], esize: u32) {
    let len = ((esize + 31) >> 5) as usize;
    // Generate len 32-bit words of randomness into x[1..1+len].
    let mut bytes = vec![0u8; len * 4];
    rng.generate(&mut bytes);
    for u in 0..len {
        x[1 + u] = u32::from_le_bytes([
            bytes[4 * u],
            bytes[4 * u + 1],
            bytes[4 * u + 2],
            bytes[4 * u + 3],
        ]);
    }
    for u in 1..len {
        x[u] &= 0x7FFFFFFF;
    }
    let m = esize & 31;
    if m == 0 {
        x[len] &= 0x7FFFFFFF;
    } else {
        x[len] &= 0x7FFFFFFF >> (31 - m);
    }
}

/// Trial division: returns 1 if no small prime divides x, 0 otherwise.
/// `x` is the candidate; `t` is scratch. Assumes x odd.
fn trial_divisions(x: &[u32], t: &mut [u32]) -> u32 {
    // y = t[0..], scratch = t[1 + ((x[0]+31)>>5)..]
    let yw = 1 + (((x[0] + 31) >> 5) as usize);
    let x0i = br_i31_ninv31(x[1]);
    let (y, scratch) = t.split_at_mut(yw);
    br_i31_decode_reduce(y, &SMALL_PRIMES, SMALL_PRIMES.len(), x);
    // moddiv(y, y, x, x0i, scratch); the C calls moddiv(y, y, ...) — y is both
    // dividend and result. Our br_i31_moddiv takes x (result/dividend) and y
    // (the divisor) separately, so we must mirror the C call: moddiv(y, y, x).
    // C signature: br_i31_moddiv(x_res, y_div, m, m0i, t). Here x_res == y_div.
    let ydiv = y.to_vec();
    br_i31_moddiv(y, &ydiv, x, x0i, scratch)
}

/// Miller-Rabin: n rounds on candidate x (assumed x = 3 mod 4). Returns 1 if all
/// rounds pass.
fn miller_rabin(
    rng: &mut dyn PrngState,
    x: &[u32],
    mut n: i32,
    t: &mut [u32],
    mut tlen: usize,
    mp31: br_i31_modpow_opt_type,
) -> u32 {
    // Compute (x-1)/2 (encoded) into the front of t reinterpreted as bytes.
    let xm1d2_len = (((x[0] - (x[0] >> 5)) + 7) >> 3) as usize;
    // Encode x into a byte buffer, then shift right by one bit.
    let mut xm1d2 = vec![0u8; xm1d2_len];
    br_i31_encode(&mut xm1d2, xm1d2_len, x);
    let mut cc: u32 = 0;
    for u in 0..xm1d2_len {
        let w = xm1d2[u] as u32;
        xm1d2[u] = ((w >> 1) | cc) as u8;
        cc = w << 7;
    }
    let _ = cc;

    // Words consumed by (x-1)/2 in t (kept here as a separate buffer rather than
    // overlaying t, since we hold xm1d2 explicitly).
    let xm1d2_len_u32 = (xm1d2_len + 3) >> 2;
    let toff = xm1d2_len_u32;
    tlen -= xm1d2_len_u32;
    let t = &mut t[toff..];

    let xlen = ((x[0] + 31) >> 5) as usize;
    let asize = x[0] - 1 - EQ0((x[0] & 31) as i32);
    let x0i = br_i31_ninv31(x[1]);
    while n > 0 {
        n -= 1;
        // Generate a random base into a = t[0..]; a[0] = x[0]; a[xlen] = 0.
        {
            let a = &mut t[..1 + xlen + 1];
            a[0] = x[0];
            a[xlen] = 0;
            mkrand(rng, a, asize);
        }
        // a^((x-1)/2) mod x into t2 = t + 1 + xlen.
        let mut t2off = 1 + xlen;
        let mut t2len = tlen - 1 - xlen;
        if (t2len & 1) != 0 {
            t2off += 1;
            t2len -= 1;
        }
        {
            let (a, t2) = t.split_at_mut(t2off);
            let a = &mut a[..1 + xlen];
            mp31(a, &xm1d2, xm1d2_len, x, x0i, t2, t2len);
        }
        // Must obtain 1 or x-1.
        let mut eq1 = t[1] ^ 1;
        let mut eqm1 = t[1] ^ (x[1] - 1);
        for u in 2..=xlen {
            eq1 |= t[u];
            eqm1 |= t[u] ^ x[u];
        }
        if (EQ0(eq1 as i32) | EQ0(eqm1 as i32)) == 0 {
            return 0;
        }
    }
    1
}

/// Create a random prime of the provided encoded bit length `esize`; the two top
/// and two bottom bits are forced to 1.
fn mkprime(
    rng: &mut dyn PrngState,
    x: &mut [u32],
    esize: u32,
    pubexp: u32,
    t: &mut [u32],
    tlen: usize,
    mp31: br_i31_modpow_opt_type,
) {
    x[0] = esize;
    let len = ((esize + 31) >> 5) as usize;
    loop {
        mkrand(rng, x, esize);
        if (esize & 31) == 0 {
            x[len] |= 0x60000000;
        } else if (esize & 31) == 1 {
            x[len] |= 0x00000001;
            x[len - 1] |= 0x40000000;
        } else {
            x[len] |= 0x00000003 << ((esize & 31) - 2);
        }
        x[1] |= 0x00000003;

        // Trial division with low primes (3, 5, 7, 11).
        let mut m3: u32 = 0;
        let mut m5: u32 = 0;
        let mut m7: u32 = 0;
        let mut m11: u32 = 0;
        let mut s7: i32 = 0;
        let mut s11: i32 = 0;
        for u in 0..len {
            let w = x[1 + u];
            let w3 = (w & 0xFFFF) + (w >> 16);
            let w5 = (w & 0xFFFF) + (w >> 16);
            let w7 = (w & 0x7FFF) + (w >> 15);
            let w11 = (w & 0xFFFFF) + (w >> 20);

            m3 += w3 << (u & 1);
            m3 = (m3 & 0xFF) + (m3 >> 8);

            m5 += w5 << ((4usize.wrapping_sub(u)) & 3);
            m5 = (m5 & 0xFFF) + (m5 >> 12);

            m7 += w7 << s7;
            m7 = (m7 & 0x1FF) + (m7 >> 9);
            s7 += 1;
            if s7 == 3 {
                s7 = 0;
            }

            m11 += w11 << s11;
            s11 += 1;
            if s11 == 10 {
                s11 = 0;
            }
            m11 = (m11 & 0x3FF) + (m11 >> 10);
        }

        m3 = (m3 & 0x3F) + (m3 >> 6);
        m3 = (m3 & 0x0F) + (m3 >> 4);
        m3 = ((m3 * 43) >> 5) & 3;

        m5 = (m5 & 0xFF) + (m5 >> 8);
        m5 = (m5 & 0x0F) + (m5 >> 4);
        m5 = m5.wrapping_sub(20 & GT(m5, 19).wrapping_neg());
        m5 = m5.wrapping_sub(10 & GT(m5, 9).wrapping_neg());
        m5 = m5.wrapping_sub(5 & GT(m5, 4).wrapping_neg());

        m7 = (m7 & 0x3F) + (m7 >> 6);
        m7 = (m7 & 0x07) + (m7 >> 3);
        m7 = ((m7 * 147) >> 7) & 7;

        // 2^5 = 32 = -1 mod 11.
        m11 = (m11 & 0x3FF) + (m11 >> 10);
        m11 = (m11 & 0x3FF) + (m11 >> 10);
        m11 = (m11 & 0x1F) + 33 - (m11 >> 5);
        m11 = m11.wrapping_sub(44 & GT(m11, 43).wrapping_neg());
        m11 = m11.wrapping_sub(22 & GT(m11, 21).wrapping_neg());
        m11 = m11.wrapping_sub(11 & GT(m11, 10).wrapping_neg());

        if m3 == 0 || m5 == 0 || m7 == 0 || m11 == 0 {
            continue;
        }
        if (pubexp == 3 && m3 == 1)
            || (pubexp == 5 && m5 == 1)
            || (pubexp == 7 && m7 == 1)
            || (pubexp == 11 && m11 == 1)
        {
            continue;
        }

        if trial_divisions(x, t) == 0 {
            continue;
        }

        let rounds: i32 = if esize < 309 {
            12
        } else if esize < 464 {
            9
        } else if esize < 670 {
            6
        } else if esize < 877 {
            4
        } else if esize < 1341 {
            3
        } else {
            2
        };

        if miller_rabin(rng, x, rounds, t, tlen, mp31) != 0 {
            return;
        }
    }
}

/// Invert public exponent modulo p-1, where m = (p-1)/2 is provided. Returns 1
/// on success, 0 on error. `d` receives 1/e mod (p-1).
fn invert_pubexp(d: &mut [u32], m: &[u32], e: u32, t: &mut [u32]) -> u32 {
    // f = t[0..]; scratch = t[1 + ((m[0]+31)>>5)..]
    let fw = 1 + (((m[0] + 31) >> 5) as usize);
    let (f, scratch) = t.split_at_mut(fw);

    br_i31_zero(d, m[0]);
    d[1] = 1;
    br_i31_zero(f, m[0]);
    f[1] = e & 0x7FFFFFFF;
    f[2] = e >> 31;
    let m0i = br_i31_ninv31(m[1]);
    let fcopy = f.to_vec();
    let r = br_i31_moddiv(d, &fcopy, m, m0i, scratch);

    // d = 1/e mod p-1; by CRT result is d or d+m. Add m if d is even.
    br_i31_add(d, m, 1 - (d[1] & 1));

    r
}

/// see inner.h
///
/// Core key-pair generation. Writes private elements into `kbuf_priv` and (if
/// `out_pub` is `Some`) public elements into it; the layout/lengths are returned
/// in [`KeygenOut`]. `sk.n_bitlen` is set. Returns `(r, layout)` where r is 1 on
/// success.
#[allow(clippy::too_many_arguments)]
pub fn br_rsa_i31_keygen_inner(
    rng: &mut dyn PrngState,
    sk: &mut br_rsa_private_key,
    kbuf_priv: &mut [u8],
    out_pub: Option<&mut [u8]>,
    size: usize,
    mut pubexp: u32,
    mp31: br_i31_modpow_opt_type,
) -> (u32, Option<KeygenOut>) {
    let mut tmp = vec![0u64; TEMPS >> 1]; // 64-bit aligned backing store
    // Reinterpret as u32 words.
    let t32: &mut [u32] = {
        let ptr = tmp.as_mut_ptr() as *mut u32;
        unsafe { std::slice::from_raw_parts_mut(ptr, TEMPS) }
    };

    if size < BR_MIN_RSA_SIZE || size > BR_MAX_RSA_SIZE {
        return (0, None);
    }
    if pubexp == 0 {
        pubexp = 3;
    } else if pubexp == 1 || (pubexp & 1) == 0 {
        return (0, None);
    }

    let esize_p0 = ((size + 1) >> 1) as u32;
    let esize_q0 = size as u32 - esize_p0;
    sk.n_bitlen = size as u32;

    // Private-key element layout (byte offsets within kbuf_priv).
    let plen = ((esize_p0 + 7) >> 3) as usize;
    let qlen = ((esize_q0 + 7) >> 3) as usize;
    let dplen = plen;
    let dqlen = qlen;
    let iqlen = plen;
    let p_boff = 0usize;
    let q_boff = p_boff + plen;
    let dp_boff = q_boff + qlen;
    let dq_boff = dp_boff + dplen;
    let iq_boff = dq_boff + dqlen;

    // Public-key element layout.
    let (nlen, elen, e_bytes) = if out_pub.is_some() {
        let nlen = (size + 7) >> 3;
        let mut e4 = [0u8; 4];
        br_enc32be(&mut e4, pubexp);
        // Trim leading zero bytes.
        let mut eoff = 0;
        while e4[eoff] == 0 {
            eoff += 1;
        }
        (nlen, 4 - eoff, e4)
    } else {
        (0, 0, [0u8; 4])
    };

    // Switch to encoded sizes.
    let esize_p = esize_p0 + (MUL31(esize_p0, 16913) >> 19) as u32;
    let esize_q = esize_q0 + (MUL31(esize_q0, 16913) >> 19) as u32;
    let plen_w = ((esize_p + 31) >> 5) as usize;
    let qlen_w = ((esize_q + 31) >> 5) as usize;
    // p = t32[0..]; q = p + 1 + plen_w; t = q + 1 + qlen_w.
    let p_off = 0usize;
    let q_off = p_off + 1 + plen_w;
    let t_off = q_off + 1 + qlen_w;
    let tlen = TEMPS - (2 + plen_w + qlen_w);

    // Generate p.
    loop {
        {
            let (head, t) = t32.split_at_mut(t_off);
            let p = &mut head[p_off..];
            mkprime(rng, p, esize_p, pubexp, t, tlen, mp31);
            br_i31_rshift(p, 1);
        }
        // invert_pubexp(t, p, pubexp, t + 1 + plen_w)
        let ok = {
            let (p_region, t) = t32.split_at_mut(t_off);
            let p = &p_region[p_off..];
            let (d, scratch) = t.split_at_mut(1 + plen_w);
            invert_pubexp(d, p, pubexp, scratch)
        };
        if ok != 0 {
            // p = (p-1)/2 -> 2*((p-1)/2)+1 = p; force low bit.
            {
                let (head, _t) = t32.split_at_mut(t_off);
                let p = &mut head[p_off..];
                br_i31_add(p, &p.to_vec(), 1);
                p[1] |= 1;
            }
            // encode sk->p and sk->dp.
            {
                let p = t32[p_off..t_off].to_vec();
                br_i31_encode(&mut kbuf_priv[p_boff..p_boff + plen], plen, &p);
                let dp = t32[t_off..t_off + 1 + plen_w].to_vec();
                br_i31_encode(&mut kbuf_priv[dp_boff..dp_boff + dplen], dplen, &dp);
            }
            break;
        }
    }

    // Generate q.
    loop {
        {
            let (head, t) = t32.split_at_mut(t_off);
            let q = &mut head[q_off..];
            mkprime(rng, q, esize_q, pubexp, t, tlen, mp31);
            br_i31_rshift(q, 1);
        }
        let ok = {
            let (q_region, t) = t32.split_at_mut(t_off);
            let q = &q_region[q_off..];
            let (d, scratch) = t.split_at_mut(1 + qlen_w);
            invert_pubexp(d, q, pubexp, scratch)
        };
        if ok != 0 {
            {
                let (head, _t) = t32.split_at_mut(t_off);
                let q = &mut head[q_off..];
                br_i31_add(q, &q.to_vec(), 1);
                q[1] |= 1;
            }
            {
                let q = t32[q_off..t_off].to_vec();
                br_i31_encode(&mut kbuf_priv[q_boff..q_boff + qlen], qlen, &q);
                let dq = t32[t_off..t_off + 1 + qlen_w].to_vec();
                br_i31_encode(&mut kbuf_priv[dq_boff..dq_boff + dqlen], dqlen, &dq);
            }
            break;
        }
    }

    // If p and q have the same size, possibly swap so that p > q.
    if esize_p == esize_q {
        let swap = {
            let (p_region, q_region) = t32.split_at_mut(q_off);
            let p = &mut p_region[p_off..];
            let q = &q_region[..];
            br_i31_sub(p, q, 0) == 1
        };
        if swap {
            // Swap p<->q words ([0, 1+plen_w)).
            for u in 0..(1 + plen_w) {
                t32.swap(p_off + u, q_off + u);
            }
            // Swap the encoded p<->q and dp<->dq byte regions.
            for u in 0..plen {
                kbuf_priv.swap(p_boff + u, q_boff + u);
            }
            for u in 0..dplen {
                kbuf_priv.swap(dp_boff + u, dq_boff + u);
            }
        }
    }

    // Compute iq = 1/q mod p. Ensure p >= q so q's header just needs updating;
    // if p has one more word, clear the extra word and bump the t pointer.
    t32[q_off] = t32[p_off]; // q[0] = p[0]
    let mut t_off2 = t_off;
    if plen_w > qlen_w {
        t32[q_off + qlen_w] = 0;
        t_off2 += 1;
    }
    {
        let p_hdr = t32[p_off];
        let (_head, t) = t32.split_at_mut(t_off2);
        // br_i31_zero(t, p[0]); t[1] = 1;
        br_i31_zero(t, p_hdr);
        t[1] = 1;
    }
    // moddiv(t, q, p, ninv31(p[1]), t + 1 + plen): result t = 1/q mod p.
    let r = {
        let m0i = br_i31_ninv31(t32[p_off + 1]);
        let (head, rest) = t32.split_at_mut(t_off2);
        let p = &head[p_off..q_off];
        let q = head[q_off..q_off + 1 + plen_w].to_vec();
        let (d, scratch) = rest.split_at_mut(1 + plen_w);
        br_i31_moddiv(d, &q, p, m0i, scratch)
    };
    br_i31_encode(&mut kbuf_priv[iq_boff..iq_boff + iqlen], iqlen, &t32[t_off2..]);

    // Compute the public modulus too, if required.
    let layout = KeygenOut {
        n_bitlen: size as u32,
        plen,
        qlen,
        dplen,
        dqlen,
        iqlen,
        nlen,
        elen,
    };
    if let Some(kbuf_pub) = out_pub {
        {
            let p_hdr = t32[p_off];
            let (head, t) = t32.split_at_mut(t_off2);
            let p = &head[p_off..q_off];
            let q = &head[q_off..q_off + 1 + plen_w];
            br_i31_zero(t, p_hdr);
            br_i31_mulacc(t, p, q);
        }
        br_i31_encode(&mut kbuf_pub[..nlen], nlen, &t32[t_off2..]);
        // e goes right after n.
        kbuf_pub[nlen..nlen + elen].copy_from_slice(&e_bytes[4 - elen..4]);
    }

    (r, Some(layout))
}
