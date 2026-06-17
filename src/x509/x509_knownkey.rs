/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! The "known key" X.509 engine (`src/x509/x509_knownkey.c`).
//!
//! This engine ignores the certificate chain entirely and returns a public key
//! that is known out-of-band (e.g. remembered from a previous connection, as in
//! the SSH model), together with a fixed set of allowed usages.

use crate::ec::br_ec_public_key;
use crate::rsa::br_rsa_public_key;
use crate::x509::{br_x509_pkey, X509Engine};

/// The "known key" X.509 engine context (`br_x509_knownkey_context`).
pub struct br_x509_knownkey_context {
    /// The configured public key (returned by `get_pkey`).
    pub pkey: br_x509_pkey,
    /// Allowed key usages (`BR_KEYTYPE_KEYX` / `BR_KEYTYPE_SIGN`).
    pub usages: u32,
}

/// see bearssl_x509.h (`br_x509_knownkey_init_rsa`)
pub fn br_x509_knownkey_init_rsa(
    pk: &br_rsa_public_key,
    usages: u32,
) -> br_x509_knownkey_context {
    br_x509_knownkey_context {
        pkey: br_x509_pkey::RSA {
            n: pk.n.to_vec(),
            e: pk.e.to_vec(),
        },
        usages,
    }
}

/// see bearssl_x509.h (`br_x509_knownkey_init_ec`)
pub fn br_x509_knownkey_init_ec(
    pk: &br_ec_public_key,
    usages: u32,
) -> br_x509_knownkey_context {
    br_x509_knownkey_context {
        pkey: br_x509_pkey::EC {
            curve: pk.curve,
            q: pk.q.to_vec(),
        },
        usages,
    }
}

impl X509Engine for br_x509_knownkey_context {
    fn start_chain(&mut self, _server_name: Option<&str>) {}
    fn start_cert(&mut self, _length: u32) {}
    fn append(&mut self, _buf: &[u8]) {}
    fn end_cert(&mut self) {}
    fn end_chain(&mut self) -> u32 {
        0
    }
    fn get_pkey(&self, usages: Option<&mut u32>) -> Option<&br_x509_pkey> {
        if let Some(u) = usages {
            *u = self.usages;
        }
        Some(&self.pkey)
    }
}
