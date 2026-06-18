/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Part of `ssl_engine.rs`: the low-level record management + record dispatch.
 * Included via `include!` so it shares the `br_ssl_engine_context` impl block.
 */

impl br_ssl_engine_context {
    /// `make_ready_in`
    pub(super) fn make_ready_in(&mut self) {
        self.ixa = 0;
        self.ixb = 0;
        self.ixc = 5;
        if self.iomode == BR_IO_IN {
            self.iomode = BR_IO_INOUT;
        }
    }

    /// `make_ready_out`
    pub(super) fn make_ready_out(&mut self) {
        let mut a = 5usize;
        let mut b = self.obuf_len() - a;
        self.out_rec.max_plaintext(&mut a, &mut b);
        let mfl = self.max_frag_len();
        if (b - a) > mfl {
            b = a + mfl;
        }
        self.oxa = a;
        self.oxb = b;
        self.oxc = a;
        if self.iomode == BR_IO_OUT {
            self.iomode = BR_IO_INOUT;
        }
    }

    /// see inner.h (`br_ssl_engine_new_max_frag_len`)
    pub fn new_max_frag_len(&mut self, max_frag_len: usize) {
        self.set16(OFF_MAX_FRAG_LEN, max_frag_len as u16);
        let nxb = self.oxc + max_frag_len;
        if self.oxa < self.oxb && self.oxb > nxb && self.oxa < nxb {
            self.oxb = nxb;
        }
    }

    /// `engine_clearbuf`
    pub(super) fn engine_clearbuf(&mut self) {
        self.make_ready_in();
        self.make_ready_out();
    }

    /// Configure the I/O buffers. Mirrors `br_ssl_engine_set_buffers_bidi` with
    /// the size of the provided buffers; we own the buffers here.
    pub fn set_buffers_bidi(&mut self, ibuf_len: usize, obuf_len: usize, shared: bool) {
        self.iomode = BR_IO_INOUT;
        self.incrypt = false;
        self.err = BR_ERR_OK;
        self.set_version_in(0);
        self.set_record_type_in(0);
        self.set16(OFF_VERSION_OUT, 0);
        self.set8(OFF_RECORD_TYPE_OUT, 0);

        self.shared_io = shared;
        self.ibuf = vec![0u8; ibuf_len];
        self.obuf = if shared {
            Vec::new()
        } else {
            vec![0u8; obuf_len]
        };

        // Compute max fragment length fitting both directions.
        let olen = if shared { ibuf_len } else { obuf_len };
        let mut u = 14u32;
        loop {
            let flen = 1usize << u;
            if olen >= flen + MAX_OUT_OVERHEAD && ibuf_len >= flen + MAX_IN_OVERHEAD {
                break;
            }
            if u == 9 {
                break;
            }
            u -= 1;
        }
        // Replicate the C loop's terminal check (`u == 8` means failure).
        let flen8 = 1usize << 9;
        if !(olen >= flen8 + MAX_OUT_OVERHEAD && ibuf_len >= flen8 + MAX_IN_OVERHEAD) && u == 9 {
            self.fail(BR_ERR_BAD_PARAM);
            return;
        }
        if u == 13 {
            u = 12;
        }
        self.set16(OFF_MAX_FRAG_LEN, (1u16) << u);
        self.set8(OFF_LOG_MAX_FRAG_LEN, u as u8);
        self.set8(OFF_PEER_LOG_MAX_FRAG_LEN, 0);

        self.out_rec = OutRec::Clear;
        self.make_ready_in();
        self.make_ready_out();
    }

    /// see bearssl_ssl.h (`br_ssl_engine_set_buffer`, monodirectional default).
    pub fn set_buffer_default(&mut self) {
        self.set_buffers_bidi(BR_SSL_BUFSIZE_MONO, BR_SSL_BUFSIZE_MONO, true);
    }

    /// Access the active output buffer (shared mode aliases the input buffer).
    pub(super) fn obuf_get(&self, off: usize) -> u8 {
        if self.shared_io {
            self.ibuf[off]
        } else {
            self.obuf[off]
        }
    }

    // ---- RNG ----------------------------------------------------------------

    /// `rng_init`
    fn rng_init(&mut self) -> bool {
        if self.rng_init_done != 0 {
            return true;
        }
        let h = if br_multihash_getimpl(&self.mhash, br_sha256_ID as i32).is_some() {
            br_multihash_getimpl(&self.mhash, br_sha256_ID as i32)
        } else if br_multihash_getimpl(&self.mhash, br_sha384_ID as i32).is_some() {
            br_multihash_getimpl(&self.mhash, br_sha384_ID as i32)
        } else {
            br_multihash_getimpl(&self.mhash, br_sha1_ID as i32)
        };
        let h = match h {
            Some(h) => h,
            None => {
                self.fail(BR_ERR_BAD_STATE);
                return false;
            }
        };
        self.rng = Some(br_hmac_drbg_context::new(h, &[]));
        self.rng_init_done = 1;
        true
    }

    /// see inner.h (`br_ssl_engine_init_rand`)
    pub fn init_rand(&mut self) -> bool {
        if !self.rng_init() {
            return false;
        }
        if !self.rng_os_rand_done {
            // OS seeding: pull from the platform RNG (getrandom-equivalent).
            let mut seed = [0u8; 32];
            if os_random(&mut seed) {
                if let Some(rng) = self.rng.as_mut() {
                    br_hmac_drbg_update(rng, &seed, seed.len());
                }
                self.rng_init_done = 2;
            }
            self.rng_os_rand_done = true;
        }
        if self.rng_init_done < 2 {
            self.fail(BR_ERR_NO_RANDOM);
            return false;
        }
        true
    }

    /// see bearssl_ssl.h (`br_ssl_engine_inject_entropy`)
    pub fn inject_entropy(&mut self, data: &[u8]) {
        if !self.rng_init() {
            return;
        }
        if let Some(rng) = self.rng.as_mut() {
            br_hmac_drbg_update(rng, data, data.len());
        }
        self.rng_init_done = 2;
    }

    // ---- low-level transport / payload windows ------------------------------

    /// `recvrec_buf`: returns `(offset, len)` window in `ibuf` for transport
    /// bytes to be written, or `(0, 0)` when none can be accepted.
    pub(super) fn recvrec_buf(&self) -> (usize, usize) {
        if self.shutdown_recv {
            return (0, 0);
        }
        match self.iomode {
            BR_IO_IN | BR_IO_INOUT => {
                if self.ixa == self.ixb {
                    let mut z = self.ixc;
                    if z > self.ibuf.len() - self.ixa {
                        z = self.ibuf.len() - self.ixa;
                    }
                    return (self.ixa, z);
                }
            }
            _ => {}
        }
        (0, 0)
    }

    /// `recvrec_ack`
    pub(super) fn recvrec_ack(&mut self, len: usize) {
        if self.iomode == BR_IO_INOUT && self.shared_io {
            self.iomode = BR_IO_IN;
        }
        self.ixa += len;
        self.ixb = self.ixa;
        self.ixc -= len;

        if self.ixa < 5 {
            return;
        }
        if self.ixa == 5 {
            self.set_record_type_in(self.ibuf[0]);
            let version = br_dec16be(&self.ibuf[1..]);
            if (version >> 8) != 3 {
                self.fail(BR_ERR_UNSUPPORTED_VERSION);
                return;
            }
            let vin = self.version_in();
            if vin != 0 && (vin as u32) != version {
                self.fail(BR_ERR_BAD_VERSION);
                return;
            }
            self.set_version_in(version as u16);

            let rlen = br_dec16be(&self.ibuf[3..]) as usize;
            if self.incrypt {
                if !self.in_rec.check_length(rlen) {
                    self.fail(BR_ERR_BAD_LENGTH);
                    return;
                }
                if rlen > (self.ibuf.len() - 5) {
                    self.fail(BR_ERR_TOO_LARGE);
                    return;
                }
            } else if rlen > 16384 {
                self.fail(BR_ERR_BAD_LENGTH);
                return;
            }

            if rlen == 0 {
                self.make_ready_in();
            } else {
                self.ixa = 5;
                self.ixb = 5;
                self.ixc = rlen;
            }
            return;
        }

        if !self.incrypt {
            self.ixa = 5;
            return;
        }
        if self.ixc != 0 {
            return;
        }

        // Full encrypted record received: decrypt in place.
        let total = self.ixa - 5;
        let res = {
            let rt = self.record_type_in() as i32;
            let ver = self.version_in() as u32;
            let payload = &mut self.ibuf[5..5 + total];
            match &mut self.in_rec {
                InRec::Clear => Some((0usize, total)),
                InRec::Gcm(cc) => gcm_decrypt(cc, rt, ver, payload),
                InRec::Chapol(cc) => chapol_decrypt(cc, rt, ver, payload),
            }
        };
        match res {
            None => {
                self.fail(BR_ERR_BAD_MAC);
            }
            Some((poff, plen)) => {
                self.ixa = 5 + poff;
                self.ixb = self.ixa + plen;
                if self.ixa == self.ixb {
                    self.make_ready_in();
                }
            }
        }
    }

    /// see inner.h (`br_ssl_engine_recvrec_finished`)
    pub(super) fn recvrec_finished(&self) -> bool {
        match self.iomode {
            BR_IO_IN | BR_IO_INOUT => self.ixc == 0 || self.ixa < 5,
            _ => true,
        }
    }

    /// `recvpld_buf` -> `(offset, len)` in `ibuf`.
    pub(super) fn recvpld_buf(&self) -> (usize, usize) {
        match self.iomode {
            BR_IO_IN | BR_IO_INOUT => {
                let len = self.ixb - self.ixa;
                if len == 0 {
                    (0, 0)
                } else {
                    (self.ixa, len)
                }
            }
            _ => (0, 0),
        }
    }

    /// `recvpld_ack`
    pub(super) fn recvpld_ack(&mut self, len: usize) {
        self.ixa += len;
        if self.ixa == self.ixb {
            if self.ixc == 0 {
                self.make_ready_in();
            } else {
                self.ixa = 5;
                self.ixb = 5;
            }
        }
    }

    /// `sendpld_buf` -> `(offset, len)` in obuf.
    pub(super) fn sendpld_buf(&self) -> (usize, usize) {
        match self.iomode {
            BR_IO_OUT | BR_IO_INOUT => {
                let len = self.oxb - self.oxa;
                if len == 0 {
                    (0, 0)
                } else {
                    (self.oxa, len)
                }
            }
            _ => (0, 0),
        }
    }

    /// `sendpld_flush`
    pub(super) fn sendpld_flush(&mut self, force: bool) {
        if self.oxa == self.oxb {
            return;
        }
        let xlen = self.oxa - self.oxc;
        if xlen == 0 && !force {
            return;
        }
        let rt = self.record_type_out() as i32;
        let ver = self.version_out() as u32;
        let po = self.oxc;
        // Borrow the active output buffer and the record context as disjoint
        // fields so both can be held mutably at once.
        let (hoff, total) = {
            let buf: &mut [u8] = if self.shared_io {
                &mut self.ibuf
            } else {
                &mut self.obuf
            };
            match &mut self.out_rec {
                OutRec::Clear => {
                    // Clear encryption: just frame the header.
                    let hoff = po - 5;
                    buf[hoff] = rt as u8;
                    br_enc16be(&mut buf[hoff + 1..], ver);
                    br_enc16be(&mut buf[hoff + 3..], xlen as u32);
                    (hoff, xlen + 5)
                }
                OutRec::Gcm(cc) => gcm_encrypt(cc, rt, ver, buf, po, xlen),
                OutRec::Chapol(cc) => chapol_encrypt(cc, rt, ver, buf, po, xlen),
            }
        };
        self.oxb = hoff;
        self.oxa = hoff;
        self.oxc = hoff + total;
    }

    /// `sendpld_ack`
    pub(super) fn sendpld_ack(&mut self, len: usize) {
        if self.iomode == BR_IO_INOUT && self.shared_io {
            self.iomode = BR_IO_OUT;
        }
        self.oxa += len;
        if self.oxa >= self.oxb {
            self.oxb = self.oxa + 1;
            self.sendpld_flush(false);
        }
    }

    /// `sendrec_buf` -> `(offset, len)` in obuf.
    pub(super) fn sendrec_buf(&self) -> (usize, usize) {
        match self.iomode {
            BR_IO_OUT | BR_IO_INOUT => {
                if self.oxc > self.oxa {
                    (self.oxa, self.oxc - self.oxa)
                } else {
                    (0, 0)
                }
            }
            _ => (0, 0),
        }
    }

    /// `sendrec_ack`
    pub(super) fn sendrec_ack(&mut self, len: usize) {
        self.oxa += len;
        self.oxb = self.oxa;
        if self.oxa == self.oxc {
            self.make_ready_out();
        }
    }

    /// `has_rec_tosend`
    pub(super) fn has_rec_tosend(&self) -> bool {
        self.oxa == self.oxb && self.oxa != self.oxc
    }

    /// `br_ssl_engine_has_pld_to_send`
    pub(super) fn has_pld_to_send(&self) -> bool {
        let xlen = self.oxa.wrapping_sub(self.oxc);
        self.oxa != self.oxb && xlen != 0 && xlen <= (self.oxb - self.oxc)
    }

}

/// Platform RNG seeding (getrandom). Returns true on success.
fn os_random(out: &mut [u8]) -> bool {
    getrandom_fill(out)
}

#[cfg(unix)]
fn getrandom_fill(out: &mut [u8]) -> bool {
    use std::fs::File;
    use std::io::Read;
    if let Ok(mut f) = File::open("/dev/urandom") {
        f.read_exact(out).is_ok()
    } else {
        false
    }
}

#[cfg(not(unix))]
fn getrandom_fill(_out: &mut [u8]) -> bool {
    false
}
