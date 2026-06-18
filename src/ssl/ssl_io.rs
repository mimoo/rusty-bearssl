/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! Simplified blocking SSL I/O (`src/ssl/ssl_io.c`).
//!
//! `br_sslio_context` wraps a `br_ssl_engine_context` together with a pair of
//! low-level transport callbacks, and exposes the synchronous `read`/`write`/
//! `flush`/`close` convenience methods. The callbacks mirror the C signatures:
//! a `low_read` that fills a buffer (returning the byte count, `0` for "would
//! block / retry", or `< 0` on error) and a `low_write` that drains one.
//!
//! Unlike the C version, the transport callbacks here are Rust closures held by
//! the context, which keeps the API idiomatic while preserving the exact
//! `run_until` control flow.

use super::ssl_engine::*;

/// Result of a low-level transport operation. Mirrors the C convention of an
/// `int` return: a non-negative byte count, or a negative error.
pub type LowResult = i32;

/// A low-level read callback: read up to `len` bytes into `data`, returning the
/// number of bytes read (`> 0`), `0` if no progress could be made yet, or a
/// negative value on error / EOF.
pub type LowRead<'a> = dyn FnMut(&mut [u8]) -> LowResult + 'a;

/// A low-level write callback: write up to `len` bytes from `data`, returning
/// the number written (`> 0`), `0` for "retry", or negative on error.
pub type LowWrite<'a> = dyn FnMut(&[u8]) -> LowResult + 'a;

/// SSL I/O wrapper context (`br_sslio_context`).
///
/// Holds a mutable borrow of the engine plus the two transport closures. The
/// engine still owns its buffers; this type only orchestrates the pumping.
pub struct br_sslio_context<'a> {
    engine: &'a mut br_ssl_engine_context,
    low_read: Box<LowRead<'a>>,
    low_write: Box<LowWrite<'a>>,
}

impl<'a> br_sslio_context<'a> {
    /// see bearssl_ssl.h (`br_sslio_init`)
    pub fn new(
        engine: &'a mut br_ssl_engine_context,
        low_read: Box<LowRead<'a>>,
        low_write: Box<LowWrite<'a>>,
    ) -> Self {
        br_sslio_context {
            engine,
            low_read,
            low_write,
        }
    }

    /// Borrow the underlying engine (e.g. to inspect `last_error`).
    pub fn engine(&self) -> &br_ssl_engine_context {
        self.engine
    }

    /// Run the engine until the target state (`SENDAPP`, `RECVAPP`, or their
    /// combination) is reached, or an error occurs. Returns `0` on success,
    /// `-1` on error. Faithful port of `run_until`.
    fn run_until(&mut self, target: u32) -> i32 {
        loop {
            let state = self.engine.current_state();
            if state & BR_SSL_CLOSED != 0 {
                return -1;
            }

            // Outgoing record data takes precedence over everything else.
            if state & BR_SSL_SENDREC != 0 {
                let (off, len) = self.engine.sendrec_buf_pub();
                let wlen = {
                    let buf = self.engine.transport_out_slice(off, len);
                    (self.low_write)(buf)
                };
                if wlen < 0 {
                    // A failed write after receiving close_notify is benign: the
                    // peer need not wait for our own close_notify response.
                    if !self.engine.shutdown_recv_flag() {
                        self.engine.fail(BR_ERR_IO);
                    }
                    return -1;
                }
                if wlen > 0 {
                    self.engine.sendrec_ack_pub(wlen as usize);
                }
                continue;
            }

            // Reached the requested target.
            if state & target != 0 {
                return 0;
            }

            // Application data must be read before we can proceed (shared
            // in/out buffer, non-half-duplex). Unrecoverable here.
            if state & BR_SSL_RECVAPP != 0 {
                return -1;
            }

            // Either there is incoming application/handshake data to read, or
            // the engine is stuck waiting for a fresh record.
            if state & BR_SSL_RECVREC != 0 {
                let (off, len) = self.engine.recvrec_buf_pub();
                let rlen = {
                    let buf = self.engine.transport_in_slice(off, len);
                    (self.low_read)(buf)
                };
                if rlen < 0 {
                    self.engine.fail(BR_ERR_IO);
                    return -1;
                }
                if rlen > 0 {
                    self.engine.recvrec_ack_pub(rlen as usize);
                }
                continue;
            }

            // Only SENDAPP set while the target is RECVAPP (shared buffer):
            // flush the buffered output to make room for a new incoming record.
            self.engine.flush(false);
        }
    }

    /// see bearssl_ssl.h (`br_sslio_read`)
    pub fn read(&mut self, dst: &mut [u8]) -> i32 {
        if dst.is_empty() {
            return 0;
        }
        if self.run_until(BR_SSL_RECVAPP) < 0 {
            return -1;
        }
        let (off, mut alen) = self.engine.recvapp_buf();
        if alen > dst.len() {
            alen = dst.len();
        }
        dst[..alen].copy_from_slice(self.engine.transport_in_slice(off, alen));
        self.engine.recvapp_ack(alen);
        alen as i32
    }

    /// see bearssl_ssl.h (`br_sslio_read_all`)
    pub fn read_all(&mut self, dst: &mut [u8]) -> i32 {
        let mut pos = 0;
        while pos < dst.len() {
            let rlen = self.read(&mut dst[pos..]);
            if rlen < 0 {
                return -1;
            }
            pos += rlen as usize;
        }
        0
    }

    /// see bearssl_ssl.h (`br_sslio_write`)
    pub fn write(&mut self, src: &[u8]) -> i32 {
        if src.is_empty() {
            return 0;
        }
        if self.run_until(BR_SSL_SENDAPP) < 0 {
            return -1;
        }
        let (off, mut alen) = self.engine.sendapp_buf();
        if alen > src.len() {
            alen = src.len();
        }
        self.engine
            .transport_out_slice(off, alen)
            .copy_from_slice(&src[..alen]);
        self.engine.sendapp_ack(alen);
        alen as i32
    }

    /// see bearssl_ssl.h (`br_sslio_write_all`)
    pub fn write_all(&mut self, src: &[u8]) -> i32 {
        let mut pos = 0;
        while pos < src.len() {
            let wlen = self.write(&src[pos..]);
            if wlen < 0 {
                return -1;
            }
            pos += wlen as usize;
        }
        0
    }

    /// see bearssl_ssl.h (`br_sslio_flush`)
    pub fn flush(&mut self) -> i32 {
        self.engine.flush(false);
        self.run_until(BR_SSL_SENDAPP | BR_SSL_RECVAPP)
    }

    /// see bearssl_ssl.h (`br_sslio_close`)
    pub fn close(&mut self) -> bool {
        self.engine.close();
        while self.engine.current_state() != BR_SSL_CLOSED {
            // Discard any incoming application data.
            self.run_until(BR_SSL_RECVAPP);
            let (_, len) = self.engine.recvapp_buf();
            if len != 0 {
                self.engine.recvapp_ack(len);
            }
        }
        self.engine.last_error() == BR_ERR_OK
    }
}

impl br_ssl_engine_context {
    /// Borrow `len` bytes of the active *output* transport buffer starting at
    /// `off` (handles the shared-buffer aliasing). Used by `br_sslio_context`.
    pub(super) fn transport_out_slice(&mut self, off: usize, len: usize) -> &mut [u8] {
        if self.shared_io {
            &mut self.ibuf[off..off + len]
        } else {
            &mut self.obuf[off..off + len]
        }
    }

    /// Borrow `len` bytes of the *input* transport buffer starting at `off`.
    pub(super) fn transport_in_slice(&mut self, off: usize, len: usize) -> &mut [u8] {
        &mut self.ibuf[off..off + len]
    }

    /// Expose the `shutdown_recv` flag for `br_sslio_context::run_until`.
    pub(super) fn shutdown_recv_flag(&self) -> bool {
        self.shutdown_recv
    }
}
