/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Key derivation functions (`src/kdf/`): HKDF (RFC 5869) and SHAKE (FIPS 202).

mod hkdf;
mod shake;

pub use hkdf::{
    br_hkdf_context, br_hkdf_flip, br_hkdf_init, br_hkdf_init_no_salt, br_hkdf_inject,
    br_hkdf_produce,
};
pub use shake::{
    br_shake_context, br_shake_flip, br_shake_init, br_shake_inject, br_shake_produce,
};
