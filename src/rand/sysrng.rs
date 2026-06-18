/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! System entropy seeder (`src/rand/sysrng.c`).
//!
//! Deviation from the C source: BearSSL selects among several OS-specific
//! seeders (RDRAND, `getentropy()`, `/dev/urandom`, Win32 `CryptGenRandom`)
//! chosen at compile time. This port provides a single portable seeder that
//! reads 32 bytes from the OS RNG and injects them via the PRNG's `update`
//! method. On Unix it reads `/dev/urandom`; the seeder name reflects the source
//! actually used. The C `br_prng_class **ctx` argument becomes the Rust PRNG
//! trait object `&mut dyn PrngState`.

use super::PrngState;

/// A PRNG seeder (`br_prng_seeder`): injects fresh OS entropy into the PRNG and
/// returns 1 on success, 0 on failure.
pub type br_prng_seeder = fn(ctx: &mut dyn PrngState) -> i32;

/// Seeder that reads from the OS RNG (`/dev/urandom` on Unix).
fn seeder_urandom(ctx: &mut dyn PrngState) -> i32 {
    use std::fs::File;
    use std::io::Read;

    let mut tmp = [0u8; 32];
    match File::open("/dev/urandom") {
        Ok(mut f) => {
            let mut filled = 0usize;
            while filled < tmp.len() {
                match f.read(&mut tmp[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            if filled == tmp.len() {
                ctx.update(&tmp);
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// see bearssl_rand.h
///
/// Returns the system seeder, writing its name through `name` if provided.
/// Unlike the C version this never returns `None`/null on the supported
/// platforms (Unix), since `/dev/urandom` is always attempted.
pub fn br_prng_seeder_system(name: Option<&mut &'static str>) -> Option<br_prng_seeder> {
    if let Some(n) = name {
        *n = "urandom";
    }
    Some(seeder_urandom)
}
