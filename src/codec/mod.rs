/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Encoding/decoding helpers (`src/codec/`).
//!
//! Mirrors BearSSL's `src/codec/` directory: range encode/decode of 16/32/64-bit
//! integers in big- and little-endian, plus the constant-time conditional copy.
//! The single-value inline helpers (`br_dec32be`, ...) live in [`crate::inner`].

mod ccopy;
mod dec16be;
mod dec16le;
mod dec32be;
mod dec32le;
mod dec64be;
mod dec64le;
mod enc16be;
mod enc16le;
mod enc32be;
mod enc32le;
mod enc64be;
mod enc64le;
// PEM encode/decode (T0-generated state machine) ported in a later pass:
// mod pemdec;
// mod pemenc;

pub use ccopy::br_ccopy;
pub use dec16be::br_range_dec16be;
pub use dec16le::br_range_dec16le;
pub use dec32be::br_range_dec32be;
pub use dec32le::br_range_dec32le;
pub use dec64be::br_range_dec64be;
pub use dec64le::br_range_dec64le;
pub use enc16be::br_range_enc16be;
pub use enc16le::br_range_enc16le;
pub use enc32be::br_range_enc32be;
pub use enc32le::br_range_enc32le;
pub use enc64be::br_range_enc64be;
pub use enc64le::br_range_enc64le;
