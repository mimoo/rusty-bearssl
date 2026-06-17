/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Part of `ssl_engine.rs`: PRF selection, master-secret / key-block derivation
 * and the record-layer switch functions (GCM and ChaCha20+Poly1305).
 */

use crate::ssl::{br_sslrec_in_chapol_init, br_sslrec_in_gcm_init, br_sslrec_out_chapol_init, br_sslrec_out_gcm_init};

impl br_ssl_engine_context {
    /// see inner.h (`br_ssl_engine_get_PRF`)
    pub(super) fn get_prf(&self, prf_id: i32) -> br_tls_prf_impl {
        if self.get16(OFF_SESSION_VERSION) >= BR_TLS12 {
            if prf_id == br_sha384_ID as i32 {
                self.prf_sha384.expect("prf_sha384 not set")
            } else {
                self.prf_sha256.expect("prf_sha256 not set")
            }
        } else {
            self.prf10.expect("prf10 not set")
        }
    }

    /// see inner.h (`br_ssl_engine_compute_master`)
    pub(super) fn compute_master(&mut self, prf_id: i32, pms: &[u8]) {
        let mut cr = [0u8; 32];
        let mut sr = [0u8; 32];
        cr.copy_from_slice(&self.mem[OFF_CLIENT_RANDOM..OFF_CLIENT_RANDOM + 32]);
        sr.copy_from_slice(&self.mem[OFF_SERVER_RANDOM..OFF_SERVER_RANDOM + 32]);
        let seed = [
            br_tls_prf_seed_chunk { data: &cr },
            br_tls_prf_seed_chunk { data: &sr },
        ];
        let iprf = self.get_prf(prf_id);
        let mut ms = [0u8; 48];
        iprf(&mut ms, pms, b"master secret", &seed);
        self.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + 48].copy_from_slice(&ms);
    }

    /// `compute_key_block`: writes `2*half_len` bytes into `kb`.
    fn compute_key_block(&self, prf_id: i32, half_len: usize, kb: &mut [u8]) {
        let mut cr = [0u8; 32];
        let mut sr = [0u8; 32];
        cr.copy_from_slice(&self.mem[OFF_CLIENT_RANDOM..OFF_CLIENT_RANDOM + 32]);
        sr.copy_from_slice(&self.mem[OFF_SERVER_RANDOM..OFF_SERVER_RANDOM + 32]);
        // key expansion uses server_random first, then client_random.
        let seed = [
            br_tls_prf_seed_chunk { data: &sr },
            br_tls_prf_seed_chunk { data: &cr },
        ];
        let mut ms = [0u8; 48];
        ms.copy_from_slice(&self.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + 48]);
        let iprf = self.get_prf(prf_id);
        iprf(&mut kb[..half_len << 1], &ms, b"key expansion", &seed);
    }

    /// see inner.h (`br_ssl_engine_switch_gcm_in`)
    pub(super) fn switch_gcm_in(&mut self, is_client: bool, prf_id: i32, cipher_key_len: usize) {
        let mut kb = [0u8; 72];
        self.compute_key_block(prf_id, cipher_key_len + 4, &mut kb);
        let (cipher_key, iv): (&[u8], &[u8]) = if is_client {
            (
                &kb[cipher_key_len..cipher_key_len * 2],
                &kb[(cipher_key_len << 1) + 4..(cipher_key_len << 1) + 8],
            )
        } else {
            (&kb[0..cipher_key_len], &kb[cipher_key_len << 1..(cipher_key_len << 1) + 4])
        };
        let bc = self.iaes_ctr.expect("aes_ctr not set");
        let gh = self.ighash.expect("ghash not set");
        self.in_rec = InRec::Gcm(br_sslrec_in_gcm_init(bc, cipher_key, gh, iv));
        self.incrypt = true;
    }

    /// see inner.h (`br_ssl_engine_switch_gcm_out`)
    pub(super) fn switch_gcm_out(&mut self, is_client: bool, prf_id: i32, cipher_key_len: usize) {
        let mut kb = [0u8; 72];
        self.compute_key_block(prf_id, cipher_key_len + 4, &mut kb);
        let (cipher_key, iv): (&[u8], &[u8]) = if is_client {
            (&kb[0..cipher_key_len], &kb[cipher_key_len << 1..(cipher_key_len << 1) + 4])
        } else {
            (
                &kb[cipher_key_len..cipher_key_len * 2],
                &kb[(cipher_key_len << 1) + 4..(cipher_key_len << 1) + 8],
            )
        };
        let bc = self.iaes_ctr.expect("aes_ctr not set");
        let gh = self.ighash.expect("ghash not set");
        self.out_rec = OutRec::Gcm(br_sslrec_out_gcm_init(bc, cipher_key, gh, iv));
    }

    /// see inner.h (`br_ssl_engine_switch_chapol_in`)
    pub(super) fn switch_chapol_in(&mut self, is_client: bool, prf_id: i32) {
        let mut kb = [0u8; 88];
        self.compute_key_block(prf_id, 44, &mut kb);
        let (cipher_key, iv): (&[u8], &[u8]) = if is_client {
            (&kb[32..64], &kb[76..88])
        } else {
            (&kb[0..32], &kb[64..76])
        };
        let ichacha = self.ichacha.expect("chacha not set");
        let ipoly = self.ipoly.expect("poly1305 not set");
        self.in_rec = InRec::Chapol(br_sslrec_in_chapol_init(ichacha, ipoly, cipher_key, iv));
        self.incrypt = true;
    }

    /// see inner.h (`br_ssl_engine_switch_chapol_out`)
    pub(super) fn switch_chapol_out(&mut self, is_client: bool, prf_id: i32) {
        let mut kb = [0u8; 88];
        self.compute_key_block(prf_id, 44, &mut kb);
        let (cipher_key, iv): (&[u8], &[u8]) = if is_client {
            (&kb[0..32], &kb[64..76])
        } else {
            (&kb[32..64], &kb[76..88])
        };
        let ichacha = self.ichacha.expect("chacha not set");
        let ipoly = self.ipoly.expect("poly1305 not set");
        self.out_rec = OutRec::Chapol(br_sslrec_out_chapol_init(ichacha, ipoly, cipher_key, iv));
    }
}
