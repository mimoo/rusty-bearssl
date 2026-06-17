/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Key derivation functions (`src/kdf/`): HKDF (RFC 5869).

mod hkdf;

pub use hkdf::{
    br_hkdf_context, br_hkdf_flip, br_hkdf_init, br_hkdf_init_no_salt, br_hkdf_inject,
    br_hkdf_produce,
};
