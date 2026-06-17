/* Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt) */

use crate::inner::br_dec64le;

/// see inner.h
pub fn br_range_dec64le(v: &mut [u64], num: usize, src: &[u8]) {
    let mut off = 0;
    for item in v.iter_mut().take(num) {
        *item = br_dec64le(&src[off..]) as u64;
        off += 8;
    }
}
