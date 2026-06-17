/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Part of `ssl_engine.rs`: the public engine API + handshake-processor coupling
 * (record-type dispatch, close, renegotiate, flush, state).
 */

impl br_ssl_engine_context {
    /// see bearssl_ssl.h (`br_ssl_engine_set_suites`)
    pub fn set_suites(&mut self, suites: &[u16]) {
        if suites.len() > BR_MAX_CIPHER_SUITES {
            self.fail(BR_ERR_BAD_PARAM);
            return;
        }
        for (i, s) in suites.iter().enumerate() {
            self.set16(OFF_SUITES_BUF + i * 2, *s);
        }
        self.set8(OFF_SUITES_NUM, suites.len() as u8);
    }

    /// `jump_handshake`: give control to the T0 handshake processor.
    pub(super) fn jump_handshake(&mut self, mut action: i32) {
        loop {
            // Input buffer for handshake (never application data).
            let (in_off, mut hlen_in) = self.recvpld_buf();
            if hlen_in != 0 && self.record_type_in() == BR_SSL_APPLICATION_DATA {
                hlen_in = 0;
            }
            self.hbuf_in_off = in_off;
            self.hbuf_in_owner = if hlen_in != 0 { HBuf::Input } else { HBuf::None };

            // Output buffer.
            let (out_off, mut hlen_out) = self.sendpld_buf();
            if hlen_out != 0 && self.has_pld_to_send() {
                hlen_out = 0;
            }
            self.hbuf_out_off = out_off;
            self.saved_hbuf_out_off = out_off;

            self.hlen_in = hlen_in;
            self.hlen_out = hlen_out;
            self.action = action as u8;

            self.run_handshake();

            if self.closed() {
                return;
            }
            if self.hbuf_out_off != self.saved_hbuf_out_off {
                self.sendpld_ack(self.hbuf_out_off - self.saved_hbuf_out_off);
            }
            if hlen_in != self.hlen_in {
                self.recvpld_ack(hlen_in - self.hlen_in);
                if self.hlen_in == 0 {
                    action = 0;
                    continue;
                }
            }
            break;
        }
    }

    /// Dispatch to the configured T0 handshake program.
    pub(super) fn run_handshake(&mut self) {
        match self.hsrun {
            Some(HsKind::Client) => crate::ssl::ssl_hs_client::br_ssl_hs_client_run(self),
            Some(HsKind::Server) => crate::ssl::ssl_hs_server::br_ssl_hs_server_run(self),
            None => {}
        }
    }

    /// see inner.h (`br_ssl_engine_flush_record`)
    pub(super) fn flush_record(&mut self) {
        if self.hbuf_out_off != self.saved_hbuf_out_off {
            self.sendpld_ack(self.hbuf_out_off - self.saved_hbuf_out_off);
        }
        if self.has_pld_to_send() {
            self.sendpld_flush(false);
        }
        let (off, len) = self.sendpld_buf();
        self.hbuf_out_off = off;
        self.saved_hbuf_out_off = off;
        self.hlen_out = len;
    }

    // ---- application data API ----------------------------------------------

    /// see bearssl_ssl.h (`br_ssl_engine_sendapp_buf`) -> (offset, len) in obuf.
    pub fn sendapp_buf(&self) -> (usize, usize) {
        if (self.application_data() & 1) == 0 {
            return (0, 0);
        }
        self.sendpld_buf()
    }

    /// see bearssl_ssl.h (`br_ssl_engine_sendapp_ack`)
    pub fn sendapp_ack(&mut self, len: usize) {
        self.sendpld_ack(len);
    }

    /// Copy application data to send into the engine output buffer; returns the
    /// number of bytes accepted. Convenience over `sendapp_buf` + write + ack.
    pub fn sendapp(&mut self, data: &[u8]) -> usize {
        let (off, len) = self.sendapp_buf();
        if len == 0 {
            return 0;
        }
        let n = len.min(data.len());
        if self.shared_io {
            self.ibuf[off..off + n].copy_from_slice(&data[..n]);
        } else {
            self.obuf[off..off + n].copy_from_slice(&data[..n]);
        }
        self.sendapp_ack(n);
        n
    }

    /// see bearssl_ssl.h (`br_ssl_engine_recvapp_buf`) -> (offset, len) in ibuf.
    pub fn recvapp_buf(&self) -> (usize, usize) {
        if (self.application_data() & 1) == 0 || self.record_type_in() != BR_SSL_APPLICATION_DATA {
            return (0, 0);
        }
        self.recvpld_buf()
    }

    /// see bearssl_ssl.h (`br_ssl_engine_recvapp_ack`)
    pub fn recvapp_ack(&mut self, len: usize) {
        self.recvpld_ack(len);
    }

    /// Read available application data into `out`; returns bytes copied.
    pub fn recvapp(&mut self, out: &mut [u8]) -> usize {
        let (off, len) = self.recvapp_buf();
        if len == 0 {
            return 0;
        }
        let n = len.min(out.len());
        out[..n].copy_from_slice(&self.ibuf[off..off + n]);
        self.recvapp_ack(n);
        n
    }

    // ---- record (transport) API --------------------------------------------

    /// see bearssl_ssl.h (`br_ssl_engine_sendrec_buf`) -> (offset, len) in obuf.
    pub fn sendrec_buf_pub(&self) -> (usize, usize) {
        self.sendrec_buf()
    }

    /// Copy outgoing record bytes into `out`; returns bytes copied + acks them.
    pub fn sendrec(&mut self, out: &mut [u8]) -> usize {
        let (off, len) = self.sendrec_buf();
        if len == 0 {
            return 0;
        }
        let n = len.min(out.len());
        if self.shared_io {
            out[..n].copy_from_slice(&self.ibuf[off..off + n]);
        } else {
            out[..n].copy_from_slice(&self.obuf[off..off + n]);
        }
        self.sendrec_ack_pub(n);
        n
    }

    /// see bearssl_ssl.h (`br_ssl_engine_sendrec_ack`)
    pub fn sendrec_ack_pub(&mut self, len: usize) {
        self.sendrec_ack(len);
        if len != 0
            && !self.has_rec_tosend()
            && (self.record_type_out() != BR_SSL_APPLICATION_DATA
                || (self.application_data() & 1) == 0)
        {
            self.jump_handshake(0);
        }
    }

    /// see bearssl_ssl.h (`br_ssl_engine_recvrec_buf`) -> (offset, len) in ibuf.
    pub fn recvrec_buf_pub(&self) -> (usize, usize) {
        self.recvrec_buf()
    }

    /// Inject transport bytes into the engine; returns bytes consumed.
    pub fn recvrec(&mut self, data: &[u8]) -> usize {
        let (off, len) = self.recvrec_buf();
        if len == 0 {
            return 0;
        }
        let n = len.min(data.len());
        self.ibuf[off..off + n].copy_from_slice(&data[..n]);
        self.recvrec_ack_pub(n);
        n
    }

    /// see bearssl_ssl.h (`br_ssl_engine_recvrec_ack`)
    pub fn recvrec_ack_pub(&mut self, len: usize) {
        self.recvrec_ack(len);
        if self.closed() {
            return;
        }
        let (_, plen) = self.recvpld_buf();
        if plen != 0 {
            match self.record_type_in() {
                BR_SSL_CHANGE_CIPHER_SPEC | BR_SSL_ALERT | BR_SSL_HANDSHAKE => {
                    self.jump_handshake(0);
                }
                BR_SSL_APPLICATION_DATA => {
                    if self.application_data() == 1 {
                        // ok, leave for the application
                    } else if self.application_data() == 2 {
                        self.recvpld_ack(plen);
                    } else {
                        self.fail(BR_ERR_UNEXPECTED);
                    }
                }
                _ => {
                    self.fail(BR_ERR_UNEXPECTED);
                }
            }
        }
    }

    /// see bearssl_ssl.h (`br_ssl_engine_close`)
    pub fn close(&mut self) {
        if !self.closed() {
            let (_, len) = self.recvapp_buf();
            if len != 0 {
                self.recvapp_ack(len);
            }
            self.jump_handshake(1);
        }
    }

    /// see bearssl_ssl.h (`br_ssl_engine_renegotiate`)
    pub fn renegotiate(&mut self) -> bool {
        let (_, applen) = self.recvapp_buf();
        if self.closed()
            || self.reneg() == 1
            || (self.flags() & BR_OPT_NO_RENEGOTIATION) != 0
            || applen != 0
        {
            return false;
        }
        self.jump_handshake(2);
        true
    }

    /// see bearssl.h (`br_ssl_engine_current_state`)
    pub fn current_state(&self) -> u32 {
        if self.closed() {
            return BR_SSL_CLOSED;
        }
        let mut s = 0u32;
        if self.sendrec_buf().1 != 0 {
            s |= BR_SSL_SENDREC;
        }
        if self.recvrec_buf().1 != 0 {
            s |= BR_SSL_RECVREC;
        }
        if self.sendapp_buf().1 != 0 {
            s |= BR_SSL_SENDAPP;
        }
        if self.recvapp_buf().1 != 0 {
            s |= BR_SSL_RECVAPP;
        }
        s
    }

    /// see bearssl_ssl.h (`br_ssl_engine_flush`)
    pub fn flush(&mut self, force: bool) {
        if !self.closed() && (self.application_data() & 1) != 0 {
            self.sendpld_flush(force);
        }
    }

    /// see inner.h (`br_ssl_engine_hs_reset`)
    pub(super) fn hs_reset(&mut self, kind: HsKind) {
        self.engine_clearbuf();
        self.dp = 0;
        self.rp = 0;
        self.hsrun = Some(kind);
        // Initialise the T0 VM (dp/rp reset + enter main).
        match kind {
            HsKind::Client => crate::ssl::ssl_hs_client::br_ssl_hs_client_init_main(self),
            HsKind::Server => crate::ssl::ssl_hs_server::br_ssl_hs_server_init_main(self),
        }
        self.shutdown_recv = false;
        self.set_application_data(0);
        self.set8(OFF_ALERT, 0);
        self.jump_handshake(0);
    }

    /// see bearssl_ssl.h (`br_ssl_key_export`) — derives keying material.
    pub fn key_export(
        &mut self,
        dst: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> bool {
        if self.application_data() != 1 {
            return false;
        }
        let mut cr = [0u8; 32];
        let mut sr = [0u8; 32];
        cr.copy_from_slice(&self.mem[OFF_CLIENT_RANDOM..OFF_CLIENT_RANDOM + 32]);
        sr.copy_from_slice(&self.mem[OFF_SERVER_RANDOM..OFF_SERVER_RANDOM + 32]);
        let mut tmp = [0u8; 2];
        let mut ms = [0u8; 48];
        ms.copy_from_slice(&self.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + 48]);
        let cs = self.get16(OFF_SESSION_CIPHER_SUITE);
        let prf_id = if suite_uses_sha384(cs) {
            BR_SSLPRF_SHA384
        } else {
            BR_SSLPRF_SHA256
        };
        let iprf = self.get_prf(prf_id);
        let chunks_buf;
        let chunks: &[br_tls_prf_seed_chunk] = if let Some(ctx) = context {
            br_enc16be(&mut tmp, ctx.len() as u32);
            chunks_buf = [
                br_tls_prf_seed_chunk { data: &cr },
                br_tls_prf_seed_chunk { data: &sr },
                br_tls_prf_seed_chunk { data: &tmp },
                br_tls_prf_seed_chunk { data: ctx },
            ];
            &chunks_buf[..]
        } else {
            chunks_buf = [
                br_tls_prf_seed_chunk { data: &cr },
                br_tls_prf_seed_chunk { data: &sr },
                br_tls_prf_seed_chunk { data: &[] },
                br_tls_prf_seed_chunk { data: &[] },
            ];
            &chunks_buf[..2]
        };
        iprf(dst, &ms, label, chunks);
        true
    }
}

/// `br_ssl_choose_hash` (`ssl_hashes.c`).
pub fn br_ssl_choose_hash(bf: u32) -> i32 {
    let pref: [u8; 5] = [
        br_sha256_ID as u8,
        br_sha384_ID as u8,
        crate::hash::br_sha512_ID as u8,
        crate::hash::br_sha224_ID as u8,
        br_sha1_ID as u8,
    ];
    for &x in pref.iter() {
        if (bf >> x) & 1 != 0 {
            return x as i32;
        }
    }
    0
}

/// Cipher suites that use SHA-384 for the TLS 1.2 PRF (`ssl_keyexport.c`).
fn suite_uses_sha384(cs: u16) -> bool {
    matches!(
        cs,
        0x009D // RSA_WITH_AES_256_GCM_SHA384
        | 0xC024 // ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        | 0xC026 // ECDH_ECDSA_WITH_AES_256_CBC_SHA384
        | 0xC028 // ECDHE_RSA_WITH_AES_256_CBC_SHA384
        | 0xC02A // ECDH_RSA_WITH_AES_256_CBC_SHA384
        | 0xC02C // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | 0xC02E // ECDH_ECDSA_WITH_AES_256_GCM_SHA384
        | 0xC030 // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | 0xC032 // ECDH_RSA_WITH_AES_256_GCM_SHA384
    )
}
