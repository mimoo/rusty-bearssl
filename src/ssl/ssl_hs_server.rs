/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `ssl_hs_server.c`: the server handshake state machine
 * plus its threaded T0 interpreter.)
 */

//! TLS server handshake processor (`src/ssl/ssl_hs_server.c`).
//!
//! Structured identically to [`super::ssl_hs_client`]; the control flow is
//! encoded in the T0 byte-code (`server_codeblock.rs`) and executed by
//! [`br_ssl_hs_server_run`]. The custom opcodes call back into the engine
//! (record I/O, key switch, crypto) and into the configured server policy.

use crate::ec::br_ec_public_key;
use crate::hash::{
    br_md5_ID, br_multihash_getimpl, br_multihash_init, br_multihash_out, br_multihash_update,
    br_sha1_ID, br_sha512_ID, BR_HASHDESC_OUT_MASK, BR_HASHDESC_OUT_OFF,
};
use crate::rand::br_hmac_drbg_generate;
use crate::rsa::{
    br_rsa_public_key, BR_HASH_OID_SHA1, BR_HASH_OID_SHA224, BR_HASH_OID_SHA256, BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
};
use crate::ssl::br_tls_prf_seed_chunk;
use crate::x509::br_x509_pkey;

use super::server_codeblock::{T0_CADDR, T0_CODEBLOCK, T0_DATABLOCK, T0_INTERPRETED};
use super::ssl_engine::*;

// ---- 7E var-int decoding (verbatim from the generated interpreter) ----------

#[inline]
fn t0_parse7E_unsigned(code: &[u8], ip: &mut usize) -> u32 {
    let mut x: u32 = 0;
    loop {
        let y = code[*ip];
        *ip += 1;
        x = (x << 7) | (y & 0x7F) as u32;
        if y < 0x80 {
            return x;
        }
    }
}

#[inline]
fn t0_parse7E_signed(code: &[u8], ip: &mut usize) -> i32 {
    let neg = ((code[*ip] >> 6) & 1) as u32;
    let mut x: u32 = 0u32.wrapping_sub(neg);
    loop {
        let y = code[*ip];
        *ip += 1;
        x = (x << 7) | (y & 0x7F) as u32;
        if y < 0x80 {
            if neg != 0 {
                return (!x as i32).wrapping_neg().wrapping_sub(1);
            } else {
                return x as i32;
            }
        }
    }
}

// ---- entry point ------------------------------------------------------------

/// see inner.h (`br_ssl_hs_server_init_main`)
pub(crate) fn br_ssl_hs_server_init_main(eng: &mut br_ssl_engine_context) {
    eng.ip = 0;
    t0_enter(eng, 166);
}

/// T0_ENTER: enter the interpreted word `slot`.
fn t0_enter(eng: &mut br_ssl_engine_context, slot: u32) {
    let mut newip = T0_CADDR[(slot - T0_INTERPRETED) as usize] as usize;
    let lnum = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut newip);
    eng.rp += lnum as usize;
    eng.rp_stack[eng.rp] = (eng.ip as u32) + (lnum << 16);
    eng.rp += 1;
    eng.ip = newip;
}

// ---- T0 data/return-stack macros --------------------------------------------

macro_rules! pop {
    ($e:expr) => {{
        $e.dp -= 1;
        $e.dp_stack[$e.dp]
    }};
}
macro_rules! popi {
    ($e:expr) => {{
        $e.dp -= 1;
        $e.dp_stack[$e.dp] as i32
    }};
}
macro_rules! push {
    ($e:expr, $v:expr) => {{
        $e.dp_stack[$e.dp] = $v;
        $e.dp += 1;
    }};
}
macro_rules! pushi {
    ($e:expr, $v:expr) => {{
        $e.dp_stack[$e.dp] = (($v) as i32) as u32;
        $e.dp += 1;
    }};
}
macro_rules! peek {
    ($e:expr, $x:expr) => {
        $e.dp_stack[$e.dp - 1 - ($x)]
    };
}
macro_rules! local {
    ($e:expr, $x:expr) => {
        $e.rp_stack[$e.rp - 2 - ($x as usize)]
    };
}

/// see inner.h (`br_ssl_hs_server_run`)
pub(crate) fn br_ssl_hs_server_run(eng: &mut br_ssl_engine_context) {
    'next: loop {
        let t0x = T0_CODEBLOCK[eng.ip] as u32;
        eng.ip += 1;
        if t0x < T0_INTERPRETED {
            match t0x {
                0 => {
                    // ret
                    eng.rp -= 1;
                    let v = eng.rp_stack[eng.rp];
                    eng.rp -= (v >> 16) as usize;
                    let v = v & 0xFFFF;
                    if v == 0 {
                        break 'next;
                    }
                    eng.ip = v as usize;
                }
                1 => {
                    let v = t0_parse7E_signed(&T0_CODEBLOCK, &mut eng.ip);
                    pushi!(eng, v);
                }
                2 => {
                    let x = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut eng.ip) as usize;
                    let v = local!(eng, x);
                    push!(eng, v);
                }
                3 => {
                    let x = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut eng.ip) as usize;
                    let v = pop!(eng);
                    local!(eng, x) = v;
                }
                4 => {
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut eng.ip);
                    eng.ip = (eng.ip as i64 + off as i64) as usize;
                }
                5 => {
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut eng.ip);
                    if pop!(eng) != 0 {
                        eng.ip = (eng.ip as i64 + off as i64) as usize;
                    }
                }
                6 => {
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut eng.ip);
                    if pop!(eng) == 0 {
                        eng.ip = (eng.ip as i64 + off as i64) as usize;
                    }
                }
                7 => {
                    // *
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_mul(b));
                }
                8 => {
                    // +
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_add(b));
                }
                9 => {
                    // -
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_sub(b));
                }
                10 => {
                    // -rot (NROT): tmp=top; top=2nd; 2nd=3rd; 3rd=tmp
                    let d = eng.dp;
                    let t = eng.dp_stack[d - 1];
                    eng.dp_stack[d - 1] = eng.dp_stack[d - 2];
                    eng.dp_stack[d - 2] = eng.dp_stack[d - 3];
                    eng.dp_stack[d - 3] = t;
                }
                11 => {
                    // <
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a < b) as i32));
                }
                12 => {
                    // <<
                    let c = popi!(eng);
                    let x = pop!(eng);
                    push!(eng, x << c);
                }
                13 => {
                    // <=
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a <= b) as i32));
                }
                14 => {
                    // <>
                    let b = pop!(eng);
                    let a = pop!(eng);
                    pushi!(eng, -((a != b) as i32));
                }
                15 => {
                    // =
                    let b = pop!(eng);
                    let a = pop!(eng);
                    pushi!(eng, -((a == b) as i32));
                }
                16 => {
                    // >
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a > b) as i32));
                }
                17 => {
                    // >=
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a >= b) as i32));
                }
                18 => {
                    // >> (arithmetic, signed)
                    let c = popi!(eng);
                    let x = popi!(eng);
                    pushi!(eng, x >> c);
                }
                19 => {
                    // and
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a & b);
                }
                20 => {
                    // begin-cert
                    if eng.chain_idx >= eng.chain.len() {
                        pushi!(eng, -1);
                    } else {
                        eng.cert_cur = eng.chain[eng.chain_idx].clone();
                        eng.cert_pos = 0;
                        eng.chain_idx += 1;
                        push!(eng, eng.cert_cur.len() as u32);
                    }
                }
                21 => {
                    // begin-ta-name (no trust anchors advertised / client auth)
                    pushi!(eng, -1);
                }
                22 => {
                    // begin-ta-name-list (cur_dn_index = 0; no-op here)
                }
                23 => {
                    // bzero
                    let len = pop!(eng) as usize;
                    let addr = pop!(eng) as usize;
                    for b in eng.mem[addr..addr + len].iter_mut() {
                        *b = 0;
                    }
                }
                24 => {
                    // call-policy-handler
                    let r = call_policy_handler(eng);
                    pushi!(eng, -((r != 0) as i32));
                }
                25 => {
                    // can-output?
                    pushi!(eng, -((eng.hlen_out > 0) as i32));
                }
                26 => {
                    // check-resume
                    if check_resume(eng) {
                        pushi!(eng, -1);
                    } else {
                        push!(eng, 0);
                    }
                }
                27 => {
                    // co
                    break 'next;
                }
                28 => {
                    // compute-Finished-inner
                    let prf_id = pop!(eng) as i32;
                    let from_client = popi!(eng);
                    compute_finished_inner(eng, from_client, prf_id);
                }
                29 => {
                    // compute-hash-CV
                    for i in 1..=6i32 {
                        let off = OFF_PAD + HASH_PAD_OFF[(i - 1) as usize] as usize;
                        let mut tmp = [0u8; 64];
                        let n = br_multihash_out(&eng.mhash, i, &mut tmp);
                        if n > 0 {
                            eng.mem[off..off + n].copy_from_slice(&tmp[..n]);
                        }
                    }
                }
                30 => {
                    // copy-cert-chunk
                    let mut clen = eng.cert_cur.len() - eng.cert_pos;
                    if clen > BR_SSL_PAD_LEN {
                        clen = BR_SSL_PAD_LEN;
                    }
                    eng.mem[OFF_PAD..OFF_PAD + clen]
                        .copy_from_slice(&eng.cert_cur[eng.cert_pos..eng.cert_pos + clen]);
                    eng.cert_pos += clen;
                    push!(eng, clen as u32);
                }
                31 => {
                    // copy-dn-chunk (no trust anchors: cur_dn_len == 0)
                    push!(eng, 0);
                }
                32 => {
                    // copy-hash-CV
                    let id = pop!(eng) as i32;
                    let off;
                    let len;
                    if id == 0 {
                        off = 0usize;
                        len = 36usize;
                    } else {
                        if br_multihash_getimpl(&eng.mhash, id).is_none() {
                            push!(eng, 0);
                            continue 'next;
                        }
                        off = HASH_PAD_OFF[(id - 1) as usize] as usize;
                        len = HASH_PAD_OFF[id as usize] as usize - off;
                    }
                    let src = OFF_PAD + off;
                    eng.hash_cv[..len].copy_from_slice(&eng.mem[src..src + len]);
                    eng.hash_cv_len = len;
                    eng.hash_cv_id = id;
                    pushi!(eng, -1);
                }
                33 => {
                    // copy-protocol-name (no ALPN configured)
                    let _idx = pop!(eng);
                    push!(eng, 0);
                }
                34 => {
                    // data-get8
                    let addr = pop!(eng) as usize;
                    push!(eng, T0_DATABLOCK[addr] as u32);
                }
                35 => {
                    // discard-input
                    eng.hlen_in = 0;
                }
                36 => {
                    // do-ecdh
                    let prf_id = popi!(eng);
                    let len = pop!(eng) as usize;
                    do_ecdh(eng, prf_id, len);
                }
                37 => {
                    // do-ecdhe-part1
                    let curve = popi!(eng);
                    let r = do_ecdhe_part1(eng, curve);
                    pushi!(eng, r);
                }
                38 => {
                    // do-ecdhe-part2
                    let prf_id = popi!(eng);
                    let len = pop!(eng) as usize;
                    do_ecdhe_part2(eng, prf_id, len);
                }
                39 => {
                    // do-rsa-decrypt
                    let prf_id = popi!(eng);
                    let len = pop!(eng) as usize;
                    do_rsa_decrypt(eng, prf_id, len);
                }
                40 => {
                    // do-static-ecdh
                    let prf_id = pop!(eng) as i32;
                    do_static_ecdh(eng, prf_id);
                }
                41 => {
                    // drop
                    let _ = pop!(eng);
                }
                42 => {
                    // dup
                    let v = peek!(eng, 0);
                    push!(eng, v);
                }
                43 => {
                    // fail
                    let e = popi!(eng);
                    eng.fail(e);
                    break 'next;
                }
                44 => {
                    // flush-record
                    eng.flush_record();
                }
                45 => {
                    // get-key-type-usages
                    let (kt, usages) = pkey_type_usages(eng);
                    if kt == 0 && usages == 0 {
                        push!(eng, 0);
                    } else {
                        push!(eng, (kt as u32) | usages);
                    }
                }
                46 => {
                    // get16
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get16(addr) as u32);
                }
                47 => {
                    // get32
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get32(addr));
                }
                48 => {
                    // get8
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get8(addr) as u32);
                }
                49 => {
                    // has-input?
                    pushi!(eng, -((eng.hlen_in != 0) as i32));
                }
                50 => {
                    // memcmp
                    let len = pop!(eng) as usize;
                    let addr2 = pop!(eng) as usize;
                    let addr1 = pop!(eng) as usize;
                    let eq = eng.mem[addr1..addr1 + len] == eng.mem[addr2..addr2 + len];
                    push!(eng, (eq as u32).wrapping_neg());
                }
                51 => {
                    // memcpy
                    let len = pop!(eng) as usize;
                    let src = pop!(eng) as usize;
                    let dst = pop!(eng) as usize;
                    eng.mem.copy_within(src..src + len, dst);
                }
                52 => {
                    // mkrand
                    let len = pop!(eng) as usize;
                    let addr = pop!(eng) as usize;
                    let mut tmp = vec![0u8; len];
                    if let Some(rng) = eng.rng.as_mut() {
                        br_hmac_drbg_generate(rng, &mut tmp, len);
                    }
                    eng.mem[addr..addr + len].copy_from_slice(&tmp);
                }
                53 => {
                    // more-incoming-bytes?
                    let v = eng.hlen_in != 0 || !eng.recvrec_finished();
                    pushi!(eng, v as i32);
                }
                54 => {
                    // multihash-init
                    br_multihash_init(&mut eng.mhash);
                }
                55 => {
                    // neg
                    let a = pop!(eng);
                    push!(eng, a.wrapping_neg());
                }
                56 => {
                    // not
                    let a = pop!(eng);
                    push!(eng, !a);
                }
                57 => {
                    // or
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a | b);
                }
                58 => {
                    // over
                    let v = peek!(eng, 1);
                    push!(eng, v);
                }
                59 => {
                    // pick
                    let x = pop!(eng) as usize;
                    let v = peek!(eng, x);
                    push!(eng, v);
                }
                60 => {
                    // read-chunk-native
                    read_chunk_native(eng);
                }
                61 => {
                    // read8-native
                    read8_native(eng);
                }
                62 => {
                    // save-session
                    if let Some(mut cache) = eng.cache.take() {
                        cache.save(eng);
                        eng.cache = Some(cache);
                    }
                }
                63 => {
                    // set-max-frag-len
                    let max_frag_len = pop!(eng) as usize;
                    eng.new_max_frag_len(max_frag_len);
                    if eng.hlen_out > max_frag_len {
                        eng.hlen_out = max_frag_len;
                    }
                }
                64 => {
                    // set16
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng) as u16;
                    eng.set16(addr, v);
                }
                65 => {
                    // set32
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng);
                    eng.set32(addr, v);
                }
                66 => {
                    // set8
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng) as u8;
                    eng.set8(addr, v);
                }
                67 => {
                    // supported-curves
                    let x = eng.iec.map(|c| c.supported_curves).unwrap_or(0);
                    push!(eng, x);
                }
                68 => {
                    // supported-hash-functions
                    let mut x = 0u32;
                    let mut num = 0u32;
                    for i in (br_sha1_ID as i32)..=(br_sha512_ID as i32) {
                        if br_multihash_getimpl(&eng.mhash, i).is_some() {
                            x |= 1u32 << i;
                            num += 1;
                        }
                    }
                    push!(eng, x);
                    push!(eng, num);
                }
                69 => {
                    // supports-ecdsa?
                    pushi!(eng, -((eng.iecdsa.is_some()) as i32));
                }
                70 => {
                    // supports-rsa-sign?
                    pushi!(eng, -((eng.irsavrfy.is_some()) as i32));
                }
                71 => {
                    // swap
                    let a = eng.dp_stack[eng.dp - 2];
                    eng.dp_stack[eng.dp - 2] = eng.dp_stack[eng.dp - 1];
                    eng.dp_stack[eng.dp - 1] = a;
                }
                72 => {
                    // switch-aesccm-in
                    let tag_len = pop!(eng) as usize;
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_ccm_in(is_client, prf_id, cipher_key_len, tag_len);
                }
                73 => {
                    // switch-aesccm-out
                    let tag_len = pop!(eng) as usize;
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_ccm_out(is_client, prf_id, cipher_key_len, tag_len);
                }
                74 => {
                    // switch-aesgcm-in
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_gcm_in(is_client, prf_id, cipher_key_len);
                }
                75 => {
                    // switch-aesgcm-out
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_gcm_out(is_client, prf_id, cipher_key_len);
                }
                76 => {
                    // switch-cbc-in
                    let cipher_key_len = pop!(eng) as usize;
                    let aes = pop!(eng) != 0;
                    let mac_id = pop!(eng) as i32;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_cbc_in(is_client, prf_id, mac_id, aes, cipher_key_len);
                }
                77 => {
                    // switch-cbc-out
                    let cipher_key_len = pop!(eng) as usize;
                    let aes = pop!(eng) != 0;
                    let mac_id = pop!(eng) as i32;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_cbc_out(is_client, prf_id, mac_id, aes, cipher_key_len);
                }
                78 => {
                    // switch-chapol-in
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_chapol_in(is_client, prf_id);
                }
                79 => {
                    // switch-chapol-out
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_chapol_out(is_client, prf_id);
                }
                80 => {
                    // ta-names-total-length (no trust anchors)
                    push!(eng, 0);
                }
                81 => {
                    // test-protocol-name (no ALPN)
                    let _len = pop!(eng);
                    pushi!(eng, -1);
                }
                82 => {
                    // total-chain-length
                    let mut total = 0u32;
                    for c in &eng.chain {
                        total += 3 + c.len() as u32;
                    }
                    push!(eng, total);
                }
                83 => {
                    // u<
                    let b = pop!(eng);
                    let a = pop!(eng);
                    pushi!(eng, -((a < b) as i32));
                }
                84 => {
                    // u>> (logical, unsigned)
                    let c = popi!(eng);
                    let x = pop!(eng);
                    push!(eng, x >> c);
                }
                85 => {
                    // verify-CV-sig
                    let sig_len = pop!(eng) as usize;
                    let err = verify_cv_sig(eng, sig_len);
                    pushi!(eng, err);
                }
                86 => {
                    // write-blob-chunk
                    write_blob_chunk(eng);
                }
                87 => {
                    // write8-native
                    write8_native(eng);
                }
                88 => {
                    // x509-append
                    let len = pop!(eng) as usize;
                    let data: Vec<u8> = eng.mem[OFF_PAD..OFF_PAD + len].to_vec();
                    if let Some(x) = eng.x509.as_mut() {
                        x.append(&data);
                    }
                }
                89 => {
                    // x509-end-cert
                    if let Some(x) = eng.x509.as_mut() {
                        x.end_cert();
                    }
                }
                90 => {
                    // x509-end-chain
                    let r = eng.x509.as_mut().map(|x| x.end_chain()).unwrap_or(0);
                    push!(eng, r);
                }
                91 => {
                    // x509-start-cert
                    let len = pop!(eng);
                    if let Some(x) = eng.x509.as_mut() {
                        x.start_cert(len);
                    }
                }
                92 => {
                    // x509-start-chain (server validates the client chain, if any)
                    let _bc = pop!(eng);
                    if let Some(x) = eng.x509.as_mut() {
                        x.start_chain(None);
                    }
                }
                _ => unreachable!("unknown T0 opcode {}", t0x),
            }
        } else {
            t0_enter(eng, t0x);
        }
    }
    // t0_exit: VM state already lives on `eng`.
}

// ---- T0 native I/O words ----------------------------------------------------

fn read_chunk_native(eng: &mut br_ssl_engine_context) {
    let clen0 = eng.hlen_in;
    if clen0 == 0 {
        return;
    }
    let len = pop!(eng);
    let addr = pop!(eng);
    let mut clen = clen0;
    if (len as usize) < clen {
        clen = len as usize;
    }
    let src = eng.hbuf_in_off;
    let chunk: Vec<u8> = eng.ibuf[src..src + clen].to_vec();
    eng.mem[addr as usize..addr as usize + clen].copy_from_slice(&chunk);
    if eng.record_type_in() == BR_SSL_HANDSHAKE {
        br_multihash_update(&mut eng.mhash, &chunk, clen);
    }
    push!(eng, addr + clen as u32);
    push!(eng, len - clen as u32);
    eng.hbuf_in_off += clen;
    eng.hlen_in -= clen;
}

fn read8_native(eng: &mut br_ssl_engine_context) {
    if eng.hlen_in > 0 {
        let x = eng.ibuf[eng.hbuf_in_off];
        eng.hbuf_in_off += 1;
        if eng.record_type_in() == BR_SSL_HANDSHAKE {
            br_multihash_update(&mut eng.mhash, &[x], 1);
        }
        push!(eng, x as u32);
        eng.hlen_in -= 1;
    } else {
        pushi!(eng, -1);
    }
}

fn write_blob_chunk(eng: &mut br_ssl_engine_context) {
    let clen0 = eng.hlen_out;
    if clen0 == 0 {
        return;
    }
    let len = pop!(eng);
    let addr = pop!(eng);
    let mut clen = clen0;
    if (len as usize) < clen {
        clen = len as usize;
    }
    let chunk: Vec<u8> = eng.mem[addr as usize..addr as usize + clen].to_vec();
    let dst = eng.hbuf_out_off;
    if eng.shared_io {
        eng.ibuf[dst..dst + clen].copy_from_slice(&chunk);
    } else {
        eng.obuf[dst..dst + clen].copy_from_slice(&chunk);
    }
    if eng.record_type_out() == BR_SSL_HANDSHAKE {
        br_multihash_update(&mut eng.mhash, &chunk, clen);
    }
    push!(eng, addr + clen as u32);
    push!(eng, len - clen as u32);
    eng.hbuf_out_off += clen;
    eng.hlen_out -= clen;
}

fn write8_native(eng: &mut br_ssl_engine_context) {
    let x = pop!(eng) as u8;
    if eng.hlen_out > 0 {
        if eng.record_type_out() == BR_SSL_HANDSHAKE {
            br_multihash_update(&mut eng.mhash, &[x], 1);
        }
        let dst = eng.hbuf_out_off;
        if eng.shared_io {
            eng.ibuf[dst] = x;
        } else {
            eng.obuf[dst] = x;
        }
        eng.hbuf_out_off += 1;
        eng.hlen_out -= 1;
        pushi!(eng, -1);
    } else {
        pushi!(eng, 0);
    }
}

// ---- C helper functions -----------------------------------------------------

/// Offsets for hash values within the pad (CertificateVerify verification).
/// Order MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; last is total length.
static HASH_PAD_OFF: [u8; 7] = [0, 16, 36, 64, 96, 144, 208];

const HASH_OID: [&[u8]; 5] = [
    BR_HASH_OID_SHA1,
    BR_HASH_OID_SHA224,
    BR_HASH_OID_SHA256,
    BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
];

fn pkey(eng: &br_ssl_engine_context) -> Option<&br_x509_pkey> {
    eng.x509.as_ref().and_then(|x| x.get_pkey(None))
}

fn pkey_type_usages(eng: &mut br_ssl_engine_context) -> (u8, u32) {
    let mut usages = 0u32;
    let kt = match eng.x509.as_ref() {
        Some(x) => match x.get_pkey(Some(&mut usages)) {
            Some(pk) => pk.key_type(),
            None => return (0, 0),
        },
        None => return (0, 0),
    };
    (kt, usages)
}

/// `call-policy-handler`: invoke the server policy `choose`, then copy the
/// chosen cipher suite / signature algo / chain into the engine. Returns the C
/// return value (1 = a suite was chosen).
fn call_policy_handler(eng: &mut br_ssl_engine_context) -> i32 {
    let policy = match eng.policy.take() {
        Some(p) => p,
        None => return 0,
    };
    let version = eng.get16(OFF_SESSION_VERSION);
    let hashes = eng.get32(OFF_SRV_HASHES);
    let st_num = eng.get8(OFF_SRV_CLIENT_SUITES_NUM) as usize;
    let mut suites: Vec<(u16, u16)> = Vec::with_capacity(st_num);
    for u in 0..st_num {
        let base = OFF_SRV_CLIENT_SUITES + u * 4;
        let id = eng.get16(base);
        let flags = eng.get16(base + 2);
        suites.push((id, flags));
    }
    let r = {
        let ctx = ServerChooseCtx {
            version,
            client_suites: &suites,
            hashes,
        };
        match policy.choose(&ctx) {
            Some(choices) => {
                eng.set16(OFF_SESSION_CIPHER_SUITE, choices.cipher_suite);
                eng.set16(OFF_SRV_SIGN_HASH_ID, choices.algo_id as u16);
                eng.chain = choices.chain;
                eng.chain_idx = 0;
                1
            }
            None => 0,
        }
    };
    eng.policy = Some(policy);
    r
}

/// `check-resume`: session resumption via the optional cache.
fn check_resume(eng: &mut br_ssl_engine_context) -> bool {
    if eng.get8(OFF_SESSION_ID_LEN) != 32 {
        return false;
    }
    if let Some(mut cache) = eng.cache.take() {
        let r = cache.load(eng);
        eng.cache = Some(cache);
        r
    } else {
        false
    }
}

/// `compute-Finished-inner`
fn compute_finished_inner(eng: &mut br_ssl_engine_context, from_client: i32, prf_id: i32) {
    let mut tmp = [0u8; 48];
    let seed_len;
    if eng.get16(OFF_SESSION_VERSION) >= BR_TLS12 {
        seed_len = br_multihash_out(&eng.mhash, prf_id, &mut tmp);
    } else {
        br_multihash_out(&eng.mhash, br_md5_ID as i32, &mut tmp);
        br_multihash_out(&eng.mhash, br_sha1_ID as i32, &mut tmp[16..]);
        seed_len = 36;
    }
    let prf = eng.get_prf(prf_id);
    let mut ms = [0u8; 48];
    ms.copy_from_slice(&eng.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + 48]);
    let label: &[u8] = if from_client != 0 {
        b"client finished"
    } else {
        b"server finished"
    };
    let seed = [br_tls_prf_seed_chunk {
        data: &tmp[..seed_len],
    }];
    let mut out = [0u8; 12];
    prf(&mut out, &ms, label, &seed);
    eng.mem[OFF_PAD..OFF_PAD + 12].copy_from_slice(&out);
}

/// `hash_data`: hash `src` with `hash_id` (or MD5+SHA-1 if 0) into `dst`.
fn hash_data(eng: &br_ssl_engine_context, hash_id: i32, src: &[u8], dst: &mut [u8]) -> usize {
    if hash_id == 0 {
        let mut tmp = [0u8; 36];
        let hf = match br_multihash_getimpl(&eng.mhash, br_md5_ID as i32) {
            Some(h) => h,
            None => return 0,
        };
        let mut hc = (hf.new)();
        hc.update(src);
        hc.out(&mut tmp);
        let hf = match br_multihash_getimpl(&eng.mhash, br_sha1_ID as i32) {
            Some(h) => h,
            None => return 0,
        };
        let mut hc = (hf.new)();
        hc.update(src);
        hc.out(&mut tmp[16..]);
        dst[..36].copy_from_slice(&tmp);
        36
    } else {
        let hf = match br_multihash_getimpl(&eng.mhash, hash_id) {
            Some(h) => h,
            None => return 0,
        };
        let mut hc = (hf.new)();
        hc.update(src);
        hc.out(dst);
        ((hf.desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK) as usize
    }
}

/// `ecdh_common`: blind the shared secret on failure, then compute the master.
fn ecdh_common(eng: &mut br_ssl_engine_context, prf_id: i32, xcoor: Vec<u8>, mut ctl: u32) {
    let mut xcoor = xcoor;
    let mut xlen = xcoor.len();
    if xlen > 80 {
        xlen = 80;
        ctl = 0;
        xcoor.truncate(80);
    }
    let mut rpms = [0u8; 80];
    if let Some(rng) = eng.rng.as_mut() {
        br_hmac_drbg_generate(rng, &mut rpms[..xlen], xlen);
    }
    // br_ccopy(ctl ^ 1, ...): overwrite with random on failure.
    if (ctl ^ 1) != 0 {
        xcoor[..xlen].copy_from_slice(&rpms[..xlen]);
    }
    eng.compute_master(prf_id, &xcoor[..xlen]);
}

/// `do_rsa_decrypt`
fn do_rsa_decrypt(eng: &mut br_ssl_engine_context, prf_id: i32, len: usize) {
    let mut epms = eng.mem[OFF_PAD..OFF_PAD + len].to_vec();
    let mut declen = len;
    let x = match eng.policy.take() {
        Some(p) => {
            let r = p.do_keyx(&mut epms, &mut declen);
            eng.policy = Some(p);
            r
        }
        None => 0,
    };
    let cmv = eng.get16(OFF_SRV_CLIENT_MAX_VERSION);
    crate::inner::br_enc16be(&mut epms, cmv as u32);
    let mut rpms = [0u8; 48];
    if let Some(rng) = eng.rng.as_mut() {
        br_hmac_drbg_generate(rng, &mut rpms, 48);
    }
    if (x ^ 1) != 0 {
        epms[..48].copy_from_slice(&rpms);
    }
    eng.compute_master(prf_id, &epms[..48]);
}

/// `do_ecdh`
fn do_ecdh(eng: &mut br_ssl_engine_context, prf_id: i32, len: usize) {
    let cpoint = eng.mem[OFF_PAD..OFF_PAD + len].to_vec();
    do_ecdh_with_point(eng, prf_id, cpoint);
}

/// `do_static_ecdh`
fn do_static_ecdh(eng: &mut br_ssl_engine_context, prf_id: i32) {
    let mut cpoint = match pkey(eng) {
        Some(br_x509_pkey::EC { q, .. }) => q.clone(),
        _ => vec![0u8; 2],
    };
    if cpoint.len() > 133 {
        cpoint.truncate(2);
    }
    do_ecdh_with_point(eng, prf_id, cpoint);
}

fn do_ecdh_with_point(eng: &mut br_ssl_engine_context, prf_id: i32, cpoint: Vec<u8>) {
    let mut cpoint = cpoint;
    let mut clen = cpoint.len();
    let x = match eng.policy.take() {
        Some(p) => {
            let r = p.do_keyx(&mut cpoint, &mut clen);
            eng.policy = Some(p);
            r
        }
        None => 0,
    };
    cpoint.truncate(clen);
    ecdh_common(eng, prf_id, cpoint, x);
}

/// `do_ecdhe_part1`: returns sig length, or `-error`.
fn do_ecdhe_part1(eng: &mut br_ssl_engine_context, curve: i32) -> i32 {
    let iec = match eng.iec {
        Some(c) => c,
        None => return -BR_ERR_INVALID_ALGORITHM,
    };
    if ((iec.supported_curves >> curve) & 1) == 0 {
        return -BR_ERR_INVALID_ALGORITHM;
    }
    eng.set8(OFF_ECDHE_CURVE, curve as u8);

    let order = (iec.order)(curve);
    let olen = order.len();
    let mut mask = 0xFFu8;
    while mask >= order[0] {
        mask >>= 1;
    }
    {
        let mut key = vec![0u8; olen];
        if let Some(rng) = eng.rng.as_mut() {
            br_hmac_drbg_generate(rng, &mut key, olen);
        }
        key[0] &= mask;
        key[olen - 1] |= 0x01;
        eng.ecdhe_key[..olen].copy_from_slice(&key);
    }
    eng.ecdhe_key_len = olen;

    // Compute our ECDH point.
    let mut point = vec![0u8; 133];
    let key = eng.ecdhe_key[..olen].to_vec();
    let glen = (iec.mulgen)(&mut point, &key, curve);
    eng.set8(OFF_ECDHE_POINT_LEN, glen as u8);
    eng.mem[OFF_ECDHE_POINT..OFF_ECDHE_POINT + glen].copy_from_slice(&point[..glen]);

    // Assemble the message to be signed.
    let cr = eng.mem[OFF_CLIENT_RANDOM..OFF_CLIENT_RANDOM + 32].to_vec();
    let sr = eng.mem[OFF_SERVER_RANDOM..OFF_SERVER_RANDOM + 32].to_vec();
    eng.mem[OFF_PAD..OFF_PAD + 32].copy_from_slice(&cr);
    eng.mem[OFF_PAD + 32..OFF_PAD + 64].copy_from_slice(&sr);
    eng.mem[OFF_PAD + 64] = 0x03;
    eng.mem[OFF_PAD + 65] = 0x00;
    eng.mem[OFF_PAD + 66] = curve as u8;
    eng.mem[OFF_PAD + 67] = glen as u8;
    eng.mem[OFF_PAD + 68..OFF_PAD + 68 + glen].copy_from_slice(&point[..glen]);
    let mut hv_len = 64 + 4 + glen;
    let algo_id = eng.get16(OFF_SRV_SIGN_HASH_ID) as u32;
    if algo_id >= 0xFF00 {
        let s = eng.mem[OFF_PAD..OFF_PAD + hv_len].to_vec();
        let mut out = [0u8; 64];
        let n = hash_data(eng, (algo_id & 0xFF) as i32, &s, &mut out);
        if n == 0 {
            return -BR_ERR_INVALID_ALGORITHM;
        }
        eng.mem[OFF_PAD..OFF_PAD + n].copy_from_slice(&out[..n]);
        hv_len = n;
    }

    let policy = match eng.policy.take() {
        Some(p) => p,
        None => return -BR_ERR_INVALID_ALGORITHM,
    };
    let mut pad = eng.mem[OFF_PAD..OFF_PAD + BR_SSL_PAD_LEN].to_vec();
    let sig_len = policy.do_sign(algo_id, &mut pad, hv_len, BR_SSL_PAD_LEN);
    eng.policy = Some(policy);
    if sig_len > 0 {
        eng.mem[OFF_PAD..OFF_PAD + sig_len].copy_from_slice(&pad[..sig_len]);
        sig_len as i32
    } else {
        -BR_ERR_INVALID_ALGORITHM
    }
}

/// `do_ecdhe_part2`
fn do_ecdhe_part2(eng: &mut br_ssl_engine_context, prf_id: i32, len: usize) {
    let curve = eng.get8(OFF_ECDHE_CURVE) as i32;
    let iec = match eng.iec {
        Some(c) => c,
        None => return,
    };
    let mut cpoint = eng.mem[OFF_PAD..OFF_PAD + len].to_vec();
    let key = eng.ecdhe_key[..eng.ecdhe_key_len].to_vec();
    let ctl = (iec.mul)(&mut cpoint, &key, curve);
    let mut xlen = 0usize;
    let xoff = (iec.xoff)(curve, &mut xlen);
    let xcoor = cpoint[xoff..xoff + xlen].to_vec();
    ecdh_common(eng, prf_id, xcoor, ctl);
    for b in eng.ecdhe_key[..eng.ecdhe_key_len].iter_mut() {
        *b = 0;
    }
}

/// `verify_CV_sig`
fn verify_cv_sig(eng: &mut br_ssl_engine_context, sig_len: usize) -> i32 {
    let id = eng.hash_cv_id;
    let hash_cv = eng.hash_cv[..eng.hash_cv_len].to_vec();
    let hash_cv_len = eng.hash_cv_len;
    let sig = eng.mem[OFF_PAD..OFF_PAD + sig_len].to_vec();
    match pkey(eng) {
        Some(br_x509_pkey::RSA { n, e }) => {
            let (n, e) = (n.clone(), e.clone());
            let irsavrfy = match eng.irsavrfy {
                Some(f) => f,
                None => return BR_ERR_BAD_SIGNATURE,
            };
            let hash_oid: Option<&[u8]> = if id == 0 {
                None
            } else {
                Some(HASH_OID[(id - 2) as usize])
            };
            let pk = br_rsa_public_key { n: &n, e: &e };
            let mut tmp = [0u8; 64];
            let r = irsavrfy(&sig, hash_oid, hash_cv_len, &pk, &mut tmp[..hash_cv_len]);
            if r != 1 || tmp[..hash_cv_len] != hash_cv[..hash_cv_len] {
                return BR_ERR_BAD_SIGNATURE;
            }
        }
        Some(br_x509_pkey::EC { curve, q }) => {
            let (curve, q) = (*curve, q.clone());
            let iecdsa = match eng.iecdsa {
                Some(f) => f,
                None => return BR_ERR_BAD_SIGNATURE,
            };
            let iec = match eng.iec {
                Some(c) => c,
                None => return BR_ERR_BAD_SIGNATURE,
            };
            let pk = br_ec_public_key { curve, q: &q };
            if iecdsa(iec, &hash_cv, &pk, &sig) != 1 {
                return BR_ERR_BAD_SIGNATURE;
            }
        }
        _ => return BR_ERR_BAD_SIGNATURE,
    }
    0
}
