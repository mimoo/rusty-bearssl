/* Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt) */

use crate::inner::br_enc64le;

/// see inner.h
pub fn br_range_enc64le(dst: &mut [u8], v: &[u64], num: usize) {
    let mut off = 0;
    for &val in v.iter().take(num) {
        br_enc64le(&mut dst[off..], val as _);
        off += 8;
    }
}
