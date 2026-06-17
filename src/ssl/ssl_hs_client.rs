/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 *
 * Automatically generated code; do not modify directly. (Faithful Rust port of
 * BearSSL's T0-generated `ssl_hs_client.c`: the client handshake state machine
 * plus its threaded T0 interpreter.)
 */

//! TLS client handshake processor (`src/ssl/ssl_hs_client.c`).
//!
//! The handshake is a coroutine driven by the engine; it consumes/produces all
//! records except application data. The control flow is encoded in the T0
//! byte-code (`client_codeblock.rs`) and executed by [`br_ssl_hs_client_run`].
//! The custom opcodes call back into the engine (record I/O, key switch,
//! crypto) exactly as the generated C calls its helper functions.

use crate::ec::br_ec_public_key;
use crate::hash::{
    br_md5_ID, br_multihash_context, br_multihash_copyimpl, br_multihash_getimpl,
    br_multihash_init, br_multihash_out, br_multihash_update, br_multihash_zero, br_sha1_ID,
    br_sha512_ID,
};
use crate::rand::br_hmac_drbg_generate;
use crate::rsa::{
    br_rsa_public_key, BR_HASH_OID_SHA1, BR_HASH_OID_SHA224, BR_HASH_OID_SHA256, BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
};
use crate::ssl::br_tls_prf_seed_chunk;
use crate::x509::br_x509_pkey;

use super::client_codeblock::{T0_CADDR, T0_CODEBLOCK, T0_DATABLOCK, T0_INTERPRETED};
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
                return !(x as i32);
            } else {
                return x as i32;
            }
        }
    }
}

// ---- entry point ------------------------------------------------------------

/// see inner.h (`br_ssl_hs_client_init_main`)
pub(crate) fn br_ssl_hs_client_init_main(eng: &mut br_ssl_engine_context) {
    eng.ip = 0;
    t0_enter(eng, 169);
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
// dp/rp are indices of the next free slot.

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

/// see inner.h (`br_ssl_hs_client_run`)
pub(crate) fn br_ssl_hs_client_run(eng: &mut br_ssl_engine_context) {
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
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_mul(b));
                }
                8 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_add(b));
                }
                9 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a.wrapping_sub(b));
                }
                10 => {
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a < b) as i32));
                }
                11 => {
                    let c = popi!(eng);
                    let x = pop!(eng);
                    push!(eng, x << c);
                }
                12 => {
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a <= b) as i32));
                }
                13 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    pushi!(eng, -((a != b) as i32));
                }
                14 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    pushi!(eng, -((a == b) as i32));
                }
                15 => {
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a > b) as i32));
                }
                16 => {
                    let b = popi!(eng);
                    let a = popi!(eng);
                    pushi!(eng, -((a >= b) as i32));
                }
                17 => {
                    let c = popi!(eng);
                    let x = popi!(eng);
                    pushi!(eng, x >> c);
                }
                18 => {
                    let _len = pop!(eng);
                }
                19 => {}
                20 => {}
                21 => {
                    let _len = pop!(eng);
                }
                22 => {}
                23 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a & b);
                }
                24 => {
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
                25 => {
                    // bzero
                    let len = pop!(eng) as usize;
                    let addr = pop!(eng) as usize;
                    for b in eng.mem[addr..addr + len].iter_mut() {
                        *b = 0;
                    }
                }
                26 => {
                    pushi!(eng, -((eng.hlen_out > 0) as i32));
                }
                27 => {
                    break 'next;
                }
                28 => {
                    let prf_id = pop!(eng) as i32;
                    let from_client = popi!(eng);
                    compute_finished_inner(eng, from_client, prf_id);
                }
                29 => {
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
                30 => {
                    let _idx = pop!(eng);
                    push!(eng, 0);
                }
                31 => {
                    let addr = pop!(eng) as usize;
                    push!(eng, T0_DATABLOCK[addr] as u32);
                }
                32 => {
                    eng.hlen_in = 0;
                }
                33 => {
                    // do-client-sign (no client auth)
                    eng.fail(BR_ERR_INVALID_ALGORITHM);
                    break 'next;
                }
                34 => {
                    let prf_id = pop!(eng) as i32;
                    let ecdhe = pop!(eng);
                    match make_pms_ecdh(eng, ecdhe, prf_id) {
                        Ok(x) => push!(eng, x as u32),
                        Err(e) => {
                            eng.fail(e);
                            break 'next;
                        }
                    }
                }
                35 => {
                    let prf_id = pop!(eng) as i32;
                    match make_pms_rsa(eng, prf_id) {
                        Ok(x) => push!(eng, x as u32),
                        Err(e) => {
                            eng.fail(e);
                            break 'next;
                        }
                    }
                }
                36 => {
                    let _prf_id = pop!(eng);
                    eng.fail(BR_ERR_INVALID_ALGORITHM);
                    break 'next;
                }
                37 => {
                    let _ = pop!(eng);
                }
                38 => {
                    let v = peek!(eng, 0);
                    push!(eng, v);
                }
                39 => {
                    push!(eng, 0);
                    continue 'next;
                }
                40 => {
                    let e = popi!(eng);
                    eng.fail(e);
                    break 'next;
                }
                41 => {
                    eng.flush_record();
                }
                42 => {
                    let _auth_types = pop!(eng);
                    eng.set8(OFF_CLI_HASH_ID, 0);
                    eng.chain.clear();
                    eng.chain_idx = 0;
                }
                43 => {
                    let (kt, usages) = pkey_type_usages(eng);
                    push!(eng, (kt as u32) | usages);
                }
                44 => {
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get16(addr) as u32);
                }
                45 => {
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get32(addr));
                }
                46 => {
                    let addr = pop!(eng) as usize;
                    push!(eng, eng.get8(addr) as u32);
                }
                47 => {
                    pushi!(eng, -((eng.hlen_in != 0) as i32));
                }
                48 => {
                    let len = pop!(eng) as usize;
                    let addr2 = pop!(eng) as usize;
                    let addr1 = pop!(eng) as usize;
                    let eq = eng.mem[addr1..addr1 + len] == eng.mem[addr2..addr2 + len];
                    push!(eng, (eq as u32).wrapping_neg());
                }
                49 => {
                    let len = pop!(eng) as usize;
                    let src = pop!(eng) as usize;
                    let dst = pop!(eng) as usize;
                    eng.mem.copy_within(src..src + len, dst);
                }
                50 => {
                    let len = pop!(eng) as usize;
                    let addr = pop!(eng) as usize;
                    let mut tmp = vec![0u8; len];
                    if let Some(rng) = eng.rng.as_mut() {
                        br_hmac_drbg_generate(rng, &mut tmp, len);
                    }
                    eng.mem[addr..addr + len].copy_from_slice(&tmp);
                }
                51 => {
                    let v = eng.hlen_in != 0 || !eng.recvrec_finished();
                    pushi!(eng, v as i32);
                }
                52 => {
                    br_multihash_init(&mut eng.mhash);
                }
                53 => {
                    let a = pop!(eng);
                    push!(eng, a.wrapping_neg());
                }
                54 => {
                    let a = pop!(eng);
                    push!(eng, !a);
                }
                55 => {
                    let b = pop!(eng);
                    let a = pop!(eng);
                    push!(eng, a | b);
                }
                56 => {
                    let v = peek!(eng, 1);
                    push!(eng, v);
                }
                57 => {
                    read_chunk_native(eng);
                }
                58 => {
                    read8_native(eng);
                }
                59 => {
                    let curve = match pkey(eng) {
                        Some(br_x509_pkey::EC { curve, .. }) => *curve,
                        _ => 0,
                    };
                    eng.set32(OFF_CLI_SERVER_CURVE, curve as u32);
                }
                60 => {
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng) as u16;
                    eng.set16(addr, v);
                }
                61 => {
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng);
                    eng.set32(addr, v);
                }
                62 => {
                    let addr = pop!(eng) as usize;
                    let v = pop!(eng) as u8;
                    eng.set8(addr, v);
                }
                63 => {
                    let addr = pop!(eng) as usize;
                    let mut n = 0;
                    while eng.mem[addr + n] != 0 {
                        n += 1;
                    }
                    push!(eng, n as u32);
                }
                64 => {
                    let x = eng.iec.map(|c| c.supported_curves).unwrap_or(0);
                    push!(eng, x);
                }
                65 => {
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
                66 => {
                    pushi!(eng, -((eng.iecdsa.is_some()) as i32));
                }
                67 => {
                    pushi!(eng, -((eng.irsavrfy.is_some()) as i32));
                }
                68 => {
                    let a = eng.dp_stack[eng.dp - 2];
                    eng.dp_stack[eng.dp - 2] = eng.dp_stack[eng.dp - 1];
                    eng.dp_stack[eng.dp - 1] = a;
                }
                69 | 70 => {
                    // switch-aesccm-in/out (unsupported)
                    let _tag = pop!(eng);
                    let _ckl = pop!(eng);
                    let _prf = pop!(eng);
                    let _ic = pop!(eng);
                    eng.fail(BR_ERR_INVALID_ALGORITHM);
                    break 'next;
                }
                71 => {
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_gcm_in(is_client, prf_id, cipher_key_len);
                }
                72 => {
                    let cipher_key_len = pop!(eng) as usize;
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_gcm_out(is_client, prf_id, cipher_key_len);
                }
                73 | 74 => {
                    // switch-cbc-in/out (unsupported in this build)
                    let _ckl = pop!(eng);
                    let _aes = pop!(eng);
                    let _mac = pop!(eng);
                    let _prf = pop!(eng);
                    let _ic = pop!(eng);
                    eng.fail(BR_ERR_INVALID_ALGORITHM);
                    break 'next;
                }
                75 => {
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_chapol_in(is_client, prf_id);
                }
                76 => {
                    let prf_id = pop!(eng) as i32;
                    let is_client = pop!(eng) != 0;
                    eng.switch_chapol_out(is_client, prf_id);
                }
                77 => {
                    let _len = pop!(eng);
                    pushi!(eng, -1);
                }
                78 => {
                    let mut total = 0u32;
                    for c in &eng.chain {
                        total += 3 + c.len() as u32;
                    }
                    push!(eng, total);
                }
                79 => {
                    let c = popi!(eng);
                    let x = pop!(eng);
                    push!(eng, x >> c);
                }
                80 => {
                    let sig_len = pop!(eng) as usize;
                    let use_rsa = popi!(eng);
                    let hash = popi!(eng);
                    let r = verify_ske_sig(eng, hash, use_rsa, sig_len);
                    push!(eng, r as u32);
                }
                81 => {
                    write_blob_chunk(eng);
                }
                82 => {
                    write8_native(eng);
                }
                83 => {
                    let len = pop!(eng) as usize;
                    let data: Vec<u8> = eng.mem[OFF_PAD..OFF_PAD + len].to_vec();
                    if let Some(x) = eng.x509.as_mut() {
                        x.append(&data);
                    }
                }
                84 => {
                    if let Some(x) = eng.x509.as_mut() {
                        x.end_cert();
                    }
                }
                85 => {
                    let r = eng.x509.as_mut().map(|x| x.end_chain()).unwrap_or(0);
                    push!(eng, r);
                }
                86 => {
                    let len = pop!(eng);
                    if let Some(x) = eng.x509.as_mut() {
                        x.start_cert(len);
                    }
                }
                87 => {
                    let bc = pop!(eng);
                    let _ = bc;
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

/// `make_pms_rsa`
fn make_pms_rsa(eng: &mut br_ssl_engine_context, prf_id: i32) -> Result<usize, i32> {
    let (n, e) = match pkey(eng) {
        Some(br_x509_pkey::RSA { n, e }) => (n.clone(), e.clone()),
        _ => return Err(BR_ERR_WRONG_KEY_USAGE),
    };
    let mut nstart = 0;
    while nstart < n.len() && n[nstart] == 0 {
        nstart += 1;
    }
    let nlen = n.len() - nstart;
    if nlen < 59 {
        return Err(crate::x509::BR_ERR_X509_WEAK_PUBLIC_KEY);
    }
    if nlen > BR_SSL_PAD_LEN {
        return Err(BR_ERR_LIMIT_EXCEEDED);
    }

    let version_max = eng.get16(OFF_VERSION_MAX);
    let pms_off = OFF_PAD + nlen - 48;
    {
        let mut pmsbuf = [0u8; 48];
        crate::inner::br_enc16be(&mut pmsbuf, version_max as u32);
        if let Some(rng) = eng.rng.as_mut() {
            br_hmac_drbg_generate(rng, &mut pmsbuf[2..48], 46);
        }
        eng.mem[pms_off..pms_off + 48].copy_from_slice(&pmsbuf);
    }
    {
        let pms = eng.mem[pms_off..pms_off + 48].to_vec();
        eng.compute_master(prf_id, &pms);
    }

    eng.mem[OFF_PAD] = 0x00;
    eng.mem[OFF_PAD + 1] = 0x02;
    eng.mem[OFF_PAD + nlen - 49] = 0x00;
    {
        let mut padbuf = vec![0u8; nlen - 51];
        if let Some(rng) = eng.rng.as_mut() {
            br_hmac_drbg_generate(rng, &mut padbuf, nlen - 51);
        }
        eng.mem[OFF_PAD + 2..OFF_PAD + 2 + (nlen - 51)].copy_from_slice(&padbuf);
    }
    for u in 2..(nlen - 49) {
        while eng.mem[OFF_PAD + u] == 0 {
            let mut b = [0u8; 1];
            if let Some(rng) = eng.rng.as_mut() {
                br_hmac_drbg_generate(rng, &mut b, 1);
            }
            eng.mem[OFF_PAD + u] = b[0];
        }
    }

    let irsapub = crate::rsa::br_rsa_public_get_default();
    let pk = br_rsa_public_key {
        n: &n[nstart..],
        e: &e,
    };
    let mut buf = eng.mem[OFF_PAD..OFF_PAD + nlen].to_vec();
    if irsapub(&mut buf, &pk) != 1 {
        return Err(BR_ERR_LIMIT_EXCEEDED);
    }
    eng.mem[OFF_PAD..OFF_PAD + nlen].copy_from_slice(&buf);
    Ok(nlen)
}

/// `make_pms_ecdh`
fn make_pms_ecdh(eng: &mut br_ssl_engine_context, ecdhe: u32, prf_id: i32) -> Result<usize, i32> {
    let (curve, point_src): (i32, Vec<u8>) = if ecdhe != 0 {
        let curve = eng.get8(OFF_ECDHE_CURVE) as i32;
        let plen = eng.get8(OFF_ECDHE_POINT_LEN) as usize;
        (
            curve,
            eng.mem[OFF_ECDHE_POINT..OFF_ECDHE_POINT + plen].to_vec(),
        )
    } else {
        match pkey(eng) {
            Some(br_x509_pkey::EC { curve, q }) => (*curve, q.clone()),
            _ => return Err(BR_ERR_INVALID_ALGORITHM),
        }
    };
    let iec = eng.iec.ok_or(BR_ERR_INVALID_ALGORITHM)?;
    if (iec.supported_curves & (1u32 << curve)) == 0 {
        return Err(BR_ERR_INVALID_ALGORITHM);
    }

    let order = (iec.order)(curve);
    let olen = order.len();
    let mut mask = 0xFFu8;
    while mask >= order[0] {
        mask >>= 1;
    }
    let mut key = vec![0u8; olen];
    if let Some(rng) = eng.rng.as_mut() {
        br_hmac_drbg_generate(rng, &mut key, olen);
    }
    key[0] &= mask;
    key[olen - 1] |= 0x01;

    let gen = (iec.generator)(curve);
    let glen = gen.len();
    if glen != point_src.len() {
        return Err(BR_ERR_INVALID_ALGORITHM);
    }
    let mut point = point_src.clone();
    if (iec.mul)(&mut point, &key, curve) != 1 {
        return Err(BR_ERR_INVALID_ALGORITHM);
    }
    let mut xlen = 0usize;
    let xoff = (iec.xoff)(curve, &mut xlen);
    {
        let pms = point[xoff..xoff + xlen].to_vec();
        eng.compute_master(prf_id, &pms);
    }
    let mut pubpoint = vec![0u8; glen.max(133)];
    let plen = (iec.mulgen)(&mut pubpoint, &key, curve);
    eng.mem[OFF_PAD..OFF_PAD + plen].copy_from_slice(&pubpoint[..plen]);
    Ok(plen)
}

const HASH_OID: [&[u8]; 5] = [
    BR_HASH_OID_SHA1,
    BR_HASH_OID_SHA224,
    BR_HASH_OID_SHA256,
    BR_HASH_OID_SHA384,
    BR_HASH_OID_SHA512,
];

/// `verify_SKE_sig`
fn verify_ske_sig(eng: &mut br_ssl_engine_context, hash: i32, use_rsa: i32, sig_len: usize) -> i32 {
    let mut mhc = br_multihash_context::default();
    br_multihash_zero(&mut mhc);
    br_multihash_copyimpl(&mut mhc, &eng.mhash);
    br_multihash_init(&mut mhc);
    let cr = eng.mem[OFF_CLIENT_RANDOM..OFF_CLIENT_RANDOM + 32].to_vec();
    let sr = eng.mem[OFF_SERVER_RANDOM..OFF_SERVER_RANDOM + 32].to_vec();
    br_multihash_update(&mut mhc, &cr, 32);
    br_multihash_update(&mut mhc, &sr, 32);
    let curve = eng.get8(OFF_ECDHE_CURVE);
    let plen = eng.get8(OFF_ECDHE_POINT_LEN);
    let head = [3u8, 0, curve, plen];
    br_multihash_update(&mut mhc, &head, 4);
    let point = eng.mem[OFF_ECDHE_POINT..OFF_ECDHE_POINT + plen as usize].to_vec();
    br_multihash_update(&mut mhc, &point, plen as usize);

    let mut hv = [0u8; 64];
    let hv_len;
    if hash != 0 {
        hv_len = br_multihash_out(&mhc, hash, &mut hv);
        if hv_len == 0 {
            return BR_ERR_INVALID_ALGORITHM;
        }
    } else {
        if br_multihash_out(&mhc, br_md5_ID as i32, &mut hv) == 0
            || br_multihash_out(&mhc, br_sha1_ID as i32, &mut hv[16..]) == 0
        {
            return BR_ERR_INVALID_ALGORITHM;
        }
        hv_len = 36;
    }

    let sig = eng.mem[OFF_PAD..OFF_PAD + sig_len].to_vec();
    if use_rsa != 0 {
        let (n, e) = match pkey(eng) {
            Some(br_x509_pkey::RSA { n, e }) => (n.clone(), e.clone()),
            _ => return BR_ERR_BAD_SIGNATURE,
        };
        let irsavrfy = match eng.irsavrfy {
            Some(f) => f,
            None => return BR_ERR_INVALID_ALGORITHM,
        };
        let hash_oid: Option<&[u8]> = if hash != 0 {
            Some(HASH_OID[(hash - 2) as usize])
        } else {
            None
        };
        let pk = br_rsa_public_key { n: &n, e: &e };
        let mut tmp = [0u8; 64];
        let r = irsavrfy(&sig, hash_oid, hv_len, &pk, &mut tmp[..hv_len]);
        if r != 1 || tmp[..hv_len] != hv[..hv_len] {
            return BR_ERR_BAD_SIGNATURE;
        }
    } else {
        let (curve, q) = match pkey(eng) {
            Some(br_x509_pkey::EC { curve, q }) => (*curve, q.clone()),
            _ => return BR_ERR_BAD_SIGNATURE,
        };
        let iecdsa = match eng.iecdsa {
            Some(f) => f,
            None => return BR_ERR_INVALID_ALGORITHM,
        };
        let iec = match eng.iec {
            Some(c) => c,
            None => return BR_ERR_INVALID_ALGORITHM,
        };
        let pk = br_ec_public_key { curve, q: &q };
        if iecdsa(iec, &hv[..hv_len], &pk, &sig) != 1 {
            return BR_ERR_BAD_SIGNATURE;
        }
    }
    0
}
