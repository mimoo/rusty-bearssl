/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Portable (constant-time) ChaCha20 (`src/symcipher/chacha20_ct.c`).

use crate::inner::{br_dec32le, br_enc32le};

/// ChaCha20 implementation function type (`br_chacha20_run` in bearssl_block.h):
/// runs ChaCha20 over `data` (encrypt/decrypt are identical) using `key` (32
/// bytes), the 12-byte `iv`, and the starting block counter `cc`. Returns the
/// counter value for the next block.
pub type br_chacha20_run = fn(key: &[u8], iv: &[u8], cc: u32, data: &mut [u8]) -> u32;

/// see bearssl_block.h
pub fn br_chacha20_ct_run(key: &[u8], iv: &[u8], mut cc: u32, data: &mut [u8]) -> u32 {
    const CW: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    let mut kw = [0u32; 8];
    let mut ivw = [0u32; 3];
    for u in 0..8 {
        kw[u] = br_dec32le(&key[u << 2..]);
    }
    for u in 0..3 {
        ivw[u] = br_dec32le(&iv[u << 2..]);
    }

    let mut off = 0;
    let mut len = data.len();
    while len > 0 {
        let mut state = [0u32; 16];
        let mut tmp = [0u8; 64];

        state[0..4].copy_from_slice(&CW);
        state[4..12].copy_from_slice(&kw);
        state[12] = cc;
        state[13..16].copy_from_slice(&ivw);

        for _ in 0..10 {
            macro_rules! QROUND {
                ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                    state[$a] = state[$a].wrapping_add(state[$b]);
                    state[$d] ^= state[$a];
                    state[$d] = (state[$d] << 16) | (state[$d] >> 16);
                    state[$c] = state[$c].wrapping_add(state[$d]);
                    state[$b] ^= state[$c];
                    state[$b] = (state[$b] << 12) | (state[$b] >> 20);
                    state[$a] = state[$a].wrapping_add(state[$b]);
                    state[$d] ^= state[$a];
                    state[$d] = (state[$d] << 8) | (state[$d] >> 24);
                    state[$c] = state[$c].wrapping_add(state[$d]);
                    state[$b] ^= state[$c];
                    state[$b] = (state[$b] << 7) | (state[$b] >> 25);
                }};
            }

            QROUND!(0, 4, 8, 12);
            QROUND!(1, 5, 9, 13);
            QROUND!(2, 6, 10, 14);
            QROUND!(3, 7, 11, 15);
            QROUND!(0, 5, 10, 15);
            QROUND!(1, 6, 11, 12);
            QROUND!(2, 7, 8, 13);
            QROUND!(3, 4, 9, 14);
        }
        for u in 0..4 {
            br_enc32le(&mut tmp[u << 2..], state[u].wrapping_add(CW[u]));
        }
        for u in 4..12 {
            br_enc32le(&mut tmp[u << 2..], state[u].wrapping_add(kw[u - 4]));
        }
        br_enc32le(&mut tmp[48..], state[12].wrapping_add(cc));
        for u in 13..16 {
            br_enc32le(&mut tmp[u << 2..], state[u].wrapping_add(ivw[u - 13]));
        }

        let clen = if len < 64 { len } else { 64 };
        for u in 0..clen {
            data[off + u] ^= tmp[u];
        }
        off += clen;
        len -= clen;
        cc = cc.wrapping_add(1);
    }
    cc
}
