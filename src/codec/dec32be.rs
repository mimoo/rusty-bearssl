/* Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt) */

use crate::inner::br_dec32be;

/// see inner.h
pub fn br_range_dec32be(v: &mut [u32], num: usize, src: &[u8]) {
    let mut off = 0;
    for item in v.iter_mut().take(num) {
        *item = br_dec32be(&src[off..]) as u32;
        off += 4;
    }
}
