/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND ...
 */

use crate::inner::MUX;

/// Conditional copy: `src` is copied into `dst` if and only if `ctl` is 1.
///
/// `dst` and `src` may overlap completely (but not partially). `len` bytes
/// are processed.
pub fn br_ccopy(ctl: u32, dst: &mut [u8], src: &[u8], len: usize) {
    for i in 0..len {
        let x = src[i] as u32;
        let y = dst[i] as u32;
        dst[i] = MUX(ctl, x, y) as u8;
    }
}
