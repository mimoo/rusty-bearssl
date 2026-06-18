/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `pemdec.c`.)
 */

//! Streamed PEM decoder (`src/codec/pemdec.c`).
//!
//! Recognises `-----BEGIN <name>-----` / `-----END <name>-----` banners and the
//! Base64 body in between, emitting decoded bytes to a caller-supplied receiver.
//! The caller pushes source bytes; decoding stops at an "event" (object start,
//! object end, or error), which must be read with [`br_pem_decoder_event`]
//! before more bytes are accepted.
//!
//! The T0 interpreter and code/data blocks are ported faithfully from the
//! generated C. The two context fields the T0 code byte-addresses (`event` and
//! `name`) are held in a flat `mem[]` buffer at their genuine upstream
//! `offsetof` values (baked into the code block); all other context fields are
//! ordinary Rust fields.

use crate::inner::{EQ, LT};
// The 7E var-int decoders are shared T0 primitives (see src/x509/t0.rs).
use crate::x509::t0::{t0_parse7E_signed, t0_parse7E_unsigned};

/// PEM event: start of object (`BR_PEM_BEGIN_OBJ`).
pub const BR_PEM_BEGIN_OBJ: i32 = 1;
/// PEM event: end of object (`BR_PEM_END_OBJ`).
pub const BR_PEM_END_OBJ: i32 = 2;
/// PEM event: decoding error (`BR_PEM_ERROR`).
pub const BR_PEM_ERROR: i32 = 3;

// ---- addressable context layout (genuine offsetof values) -------------------
//
// The generated code block bakes `offsetof(br_pem_decoder_context, event)` and
// `offsetof(..., name)`; these are the upstream values, so the code block is
// reproduced verbatim. Only these two fields are byte-addressed by the T0 code;
// everything else is a plain Rust field.

const OFF_EVENT: u32 = 320; // unsigned char
const OFF_NAME: u32 = 321; // char[128]
const MEM_LEN: usize = OFF_NAME as usize + 128;

/// PEM decoder context (`br_pem_decoder_context`).
///
/// `'a` is the lifetime of the optional decoded-data receiver callback.
pub struct br_pem_decoder_context<'a> {
    /// Flat byte buffer for the T0-addressable fields (`event`, `name`).
    mem: Box<[u8; MEM_LEN]>,

    // T0 VM state.
    dp_stack: [u32; 32],
    rp_stack: [u32; 32],
    dp: usize,
    rp: usize,
    ip: usize,

    // Current input chunk position (the chunk slice is threaded through `run`).
    hlen: usize,
    cur_pos: usize,

    // Decoded-data receiver and its accumulation buffer.
    dest: Option<&'a mut dyn FnMut(&[u8])>,
    buf: [u8; 255],
    ptr: usize,
}

impl br_pem_decoder_context<'_> {
    #[inline]
    fn get8(&self, addr: u32) -> u8 {
        self.mem[addr as usize]
    }
    #[inline]
    fn set8(&mut self, addr: u32, v: u8) {
        self.mem[addr as usize] = v;
    }

    /// see bearssl_pem.h (`br_pem_decoder_name`).
    ///
    /// Valid only when a `BR_PEM_BEGIN_OBJ` event has been raised. The name is
    /// normalised to uppercase, NUL-terminated within `name[]`.
    pub fn name(&self) -> &str {
        let start = OFF_NAME as usize;
        let bytes = &self.mem[start..];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        // The decoder only ever stores ASCII bytes here.
        core::str::from_utf8(&bytes[..end]).unwrap_or("")
    }
}

include!("pemdec_codeblock.rs");

/// see bearssl_pem.h (`br_pem_decoder_init`).
pub fn br_pem_decoder_init<'a>() -> br_pem_decoder_context<'a> {
    let mut ctx = br_pem_decoder_context {
        mem: Box::new([0u8; MEM_LEN]),
        dp_stack: [0; 32],
        rp_stack: [0; 32],
        dp: 0,
        rp: 0,
        ip: 0,
        hlen: 0,
        cur_pos: 0,
        dest: None,
        buf: [0u8; 255],
        ptr: 0,
    };
    init_main(&mut ctx);
    run(&mut ctx, &[]);
    ctx
}

/// see bearssl_pem.h (`br_pem_decoder_setdest`).
///
/// Sets the receiver for decoded object data. When an object is entered, `dest`
/// is called repeatedly with successive chunks of decoded data.
pub fn br_pem_decoder_setdest<'a>(
    ctx: &mut br_pem_decoder_context<'a>,
    dest: Option<&'a mut dyn FnMut(&[u8])>,
) {
    ctx.dest = dest;
}

/// see bearssl_pem.h (`br_pem_decoder_push`).
///
/// Returns the number of bytes actually consumed (may be less than `data.len()`
/// when an event is raised). While an event is pending, returns 0.
pub fn br_pem_decoder_push(ctx: &mut br_pem_decoder_context, data: &[u8]) -> usize {
    if ctx.get8(OFF_EVENT) != 0 {
        return 0;
    }
    ctx.hlen = data.len();
    ctx.cur_pos = 0;
    run(ctx, data);
    data.len() - ctx.hlen
}

/// see bearssl_pem.h (`br_pem_decoder_event`).
///
/// Returns the raised event (and clears it), or 0 if none is pending.
pub fn br_pem_decoder_event(ctx: &mut br_pem_decoder_context) -> i32 {
    let event = ctx.get8(OFF_EVENT) as i32;
    ctx.set8(OFF_EVENT, 0);
    event
}
