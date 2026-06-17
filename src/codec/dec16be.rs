/* Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt) */

use crate::inner::br_dec16be;

/// see inner.h
pub fn br_range_dec16be(v: &mut [u16], num: usize, src: &[u8]) {
    let mut off = 0;
    for item in v.iter_mut().take(num) {
        *item = br_dec16be(&src[off..]) as u16;
        off += 2;
    }
}
