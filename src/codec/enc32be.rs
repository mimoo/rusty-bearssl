/* Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt) */

use crate::inner::br_enc32be;

/// see inner.h
pub fn br_range_enc32be(dst: &mut [u8], v: &[u32], num: usize) {
    let mut off = 0;
    for &val in v.iter().take(num) {
        br_enc32be(&mut dst[off..], val as _);
        off += 4;
    }
}
