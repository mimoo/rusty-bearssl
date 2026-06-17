/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * bearssl-rs: an idiomatic Rust reimplementation of BearSSL, built to be
 * interoperable with the upstream C library. The crate layout mirrors
 * BearSSL's `src/` directory file-for-file; see CONVENTIONS.md.
 */

// BearSSL's C identifiers are preserved verbatim for traceability against the
// upstream source, which means some names do not follow Rust casing rules.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_swap)]
#![allow(dead_code)]

pub mod inner;

pub mod codec;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod rand;
pub mod symcipher;
