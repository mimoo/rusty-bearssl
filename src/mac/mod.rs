/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Message authentication codes (`src/mac/`): HMAC, with a constant-time
//! verification variant (`br_hmac_outCT`) for the TLS record MAC.

use crate::hash::{br_hash_class, BR_HASHDESC_LBLEN_MASK, BR_HASHDESC_LBLEN_OFF};

#[inline(always)]
fn block_size(dig: &br_hash_class) -> usize {
    let ls = (dig.desc >> BR_HASHDESC_LBLEN_OFF) & BR_HASHDESC_LBLEN_MASK;
    1usize << ls
}

mod hmac;
mod hmac_ct;

pub use hmac::{
    br_hmac_context, br_hmac_get_digest, br_hmac_init, br_hmac_key_context, br_hmac_key_get_digest,
    br_hmac_key_init, br_hmac_out, br_hmac_size, br_hmac_update,
};
pub use hmac_ct::br_hmac_outCT;
