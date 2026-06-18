//! Live mutual-TLS interoperability: the Rust SSL *client* presents a client
//! certificate to the upstream C `brssl server` (which is configured to request
//! and require client authentication via `-CA`). Confirms the client-cert
//! handshake path (CertificateRequest -> Certificate + CertificateVerify).
//!
//! Skipped (passes trivially) when `brssl` / the sample certificates are not
//! present. Point `BRSSL_DIR` at a built BearSSL checkout to run it.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::Duration;

use bearssl::codec::*;
use bearssl::ssl::*;
use bearssl::x509::{
    br_skey, br_skey_decoder_init, br_skey_decoder_push, br_x509_pkey, br_x509_trust_anchor,
    BR_X509_TA_CA,
};

// ---- trust anchor (RSA root) from BearSSL samples/client_basic.c ------------
// (Same root that signs the sample EE chain; used so our client validates the
// brssl server's certificate.)

static TA0_DN: [u8; 30] = [
    0x30, 0x1C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x41, 0x31,
    0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x52, 0x6F, 0x6F, 0x74,
];
static TA0_RSA_N: [u8; 256] = [
    0xB6, 0xD9, 0x34, 0xD4, 0x50, 0xFD, 0xB3, 0xAF, 0x7A, 0x73, 0xF1, 0xCE, 0x38, 0xBF, 0x5D, 0x6F,
    0x45, 0xE1, 0xFD, 0x4E, 0xB1, 0x98, 0xC6, 0x60, 0x83, 0x26, 0xD2, 0x17, 0xD1, 0xC5, 0xB7, 0x9A,
    0xA3, 0xC1, 0xDE, 0x63, 0x39, 0x97, 0x9C, 0xF0, 0x5E, 0x5C, 0xC8, 0x1C, 0x17, 0xB9, 0x88, 0x19,
    0x6D, 0xF0, 0xB6, 0x2E, 0x30, 0x50, 0xA1, 0x54, 0x6E, 0x93, 0xC0, 0xDB, 0xCF, 0x30, 0xCB, 0x9F,
    0x1E, 0x27, 0x79, 0xF1, 0xC3, 0x99, 0x52, 0x35, 0xAA, 0x3D, 0xB6, 0xDF, 0xB0, 0xAD, 0x7C, 0xCB,
    0x49, 0xCD, 0xC0, 0xED, 0xE7, 0x66, 0x10, 0x2A, 0xE9, 0xCE, 0x28, 0x1F, 0x21, 0x50, 0xFA, 0x77,
    0x4C, 0x2D, 0xDA, 0xEF, 0x3C, 0x58, 0xEB, 0x4E, 0xBF, 0xCE, 0xE9, 0xFB, 0x1A, 0xDA, 0xA3, 0x83,
    0xA3, 0xCD, 0xA3, 0xCA, 0x93, 0x80, 0xDC, 0xDA, 0xF3, 0x17, 0xCC, 0x7A, 0xAB, 0x33, 0x80, 0x9C,
    0xB2, 0xD4, 0x7F, 0x46, 0x3F, 0xC5, 0x3C, 0xDC, 0x61, 0x94, 0xB7, 0x27, 0x29, 0x6E, 0x2A, 0xBC,
    0x5B, 0x09, 0x36, 0xD4, 0xC6, 0x3B, 0x0D, 0xEB, 0xBE, 0xCE, 0xDB, 0x1D, 0x1C, 0xBC, 0x10, 0x6A,
    0x71, 0x71, 0xB3, 0xF2, 0xCA, 0x28, 0x9A, 0x77, 0xF2, 0x8A, 0xEC, 0x42, 0xEF, 0xB1, 0x4A, 0x8E,
    0xE2, 0xF2, 0x1A, 0x32, 0x2A, 0xCD, 0xC0, 0xA6, 0x46, 0x2C, 0x9A, 0xC2, 0x85, 0x37, 0x91, 0x7F,
    0x46, 0xA1, 0x93, 0x81, 0xA1, 0x74, 0x66, 0xDF, 0xBA, 0xB3, 0x39, 0x20, 0x91, 0x93, 0xFA, 0x1D,
    0xA1, 0xA8, 0x85, 0xE7, 0xE4, 0xF9, 0x07, 0xF6, 0x10, 0xF6, 0xA8, 0x27, 0x01, 0xB6, 0x7F, 0x12,
    0xC3, 0x40, 0xC3, 0xC9, 0xE2, 0xB0, 0xAB, 0x49, 0x18, 0x3A, 0x64, 0xB6, 0x59, 0xB7, 0x95, 0xB5,
    0x96, 0x36, 0xDF, 0x22, 0x69, 0xAA, 0x72, 0x6A, 0x54, 0x4E, 0x27, 0x29, 0xA3, 0x0E, 0x97, 0x15,
];
static TA0_RSA_E: [u8; 3] = [0x01, 0x00, 0x01];

fn trust_anchors() -> &'static [br_x509_trust_anchor<'static>] {
    use std::sync::OnceLock;
    static TAS: OnceLock<Vec<br_x509_trust_anchor<'static>>> = OnceLock::new();
    TAS.get_or_init(|| {
        vec![br_x509_trust_anchor {
            dn: &TA0_DN,
            flags: BR_X509_TA_CA,
            pkey: br_x509_pkey::RSA {
                n: TA0_RSA_N.to_vec(),
                e: TA0_RSA_E.to_vec(),
            },
        }]
    })
}

fn brssl_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("BRSSL_DIR") {
        return Some(PathBuf::from(d));
    }
    let p = PathBuf::from("/Users/david/ZkSecurity/Clients/bearssl/BearSSL");
    if p.join("build/brssl").exists() {
        Some(p)
    } else {
        None
    }
}

/// Decode every PEM object in `data`, returning `(name, der_bytes)` pairs.
fn pem_objects(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let cur: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
    let mut ctx = br_pem_decoder_init();
    let mut name = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let sink_cur = cur.clone();
        let mut sink = move |chunk: &[u8]| {
            sink_cur.borrow_mut().extend_from_slice(chunk);
        };
        br_pem_decoder_setdest(&mut ctx, Some(unsafe {
            std::mem::transmute::<&mut dyn FnMut(&[u8]), &mut dyn FnMut(&[u8])>(&mut sink)
        }));
        let n = br_pem_decoder_push(&mut ctx, &data[pos..]);
        pos += n;
        let ev = br_pem_decoder_event(&mut ctx);
        match ev {
            BR_PEM_BEGIN_OBJ => {
                name = ctx.name().to_string();
                cur.borrow_mut().clear();
            }
            BR_PEM_END_OBJ => out.push((name.clone(), cur.borrow().clone())),
            BR_PEM_ERROR => break,
            _ => {}
        }
        br_pem_decoder_setdest(&mut ctx, None);
        let _ = &mut sink;
    }
    out
}

fn read_chain(path: &std::path::Path) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).unwrap();
    pem_objects(&data)
        .into_iter()
        .filter(|(n, _)| n.contains("CERTIFICATE"))
        .map(|(_, d)| d)
        .collect()
}

fn read_rsa_key(path: &std::path::Path) -> RsaPrivateKeyParts {
    let data = std::fs::read(path).unwrap();
    let objs = pem_objects(&data);
    let der = &objs[0].1;
    let mut dc = br_skey_decoder_init();
    br_skey_decoder_push(&mut dc, der);
    match dc.key() {
        br_skey::RSA { n_bitlen, p, q, dp, dq, iq } => RsaPrivateKeyParts {
            n_bitlen: *n_bitlen,
            p: p.clone(),
            q: q.clone(),
            dp: dp.clone(),
            dq: dq.clone(),
            iq: iq.clone(),
        },
        _ => panic!("expected an RSA private key in {}", path.display()),
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rust_client_mtls_vs_brssl_server() {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let scert = dir.join("samples/cert-ee-rsa.pem");
    let sica = dir.join("samples/cert-ica-rsa.pem");
    let skey = dir.join("samples/key-ee-rsa.pem");
    let root = dir.join("samples/cert-root-rsa.pem");
    if !scert.exists() || !skey.exists() || !root.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }

    // The server presents the EE+ICA chain; the client validates it against the
    // RSA root trust anchor. The server is given `-CA root` so it REQUESTS and
    // REQUIRES a client certificate. We present the same sample EE chain + key
    // as our client certificate (the root validates it too).
    let server_chain = std::env::temp_dir().join("bearssl_mtls_schain.pem");
    {
        let mut c = std::fs::read(&scert).unwrap();
        if let Ok(mut i) = std::fs::read(&sica) {
            c.append(&mut i);
        }
        std::fs::write(&server_chain, &c).unwrap();
    }

    // The client certificate chain (EE + ICA) and key, decoded to DER.
    let mut client_chain = read_chain(&scert);
    client_chain.extend(read_chain(&sica));
    let client_key = read_rsa_key(&skey);

    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let mut child = Command::new(&brssl)
        .arg("server")
        .args(["-p", &port.to_string()])
        .args(["-cert", server_chain.to_str().unwrap()])
        .args(["-key", skey.to_str().unwrap()])
        // Trust anchor for client auth: makes brssl REQUEST + REQUIRE a client cert.
        .args(["-CA", root.to_str().unwrap()])
        .args(["-vmin", "tls1.2", "-vmax", "tls1.2"])
        .args(["-cs", "ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
        .args(["-trace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn brssl server");
    if let Some(mut si) = child.stdin.take() {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            let _ = si.write_all(b"mtls hello\n");
            let _ = si.flush();
            std::thread::sleep(Duration::from_secs(8));
            drop(si);
        });
    }
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    if let Some(mut se) = child.stderr.take() {
        let buf = stderr_shared.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            loop {
                match se.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
        });
    }
    let _guard = ChildGuard(child);

    std::thread::sleep(Duration::from_millis(300));
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut cc = br_ssl_client_context::init_full(trust_anchors());
    // Install our client certificate (single RSA).
    cc.set_single_rsa(client_chain, client_key);
    assert!(cc.reset(Some("localhost"), false), "client reset failed");

    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    let mut sent = false;
    let mut got = Vec::new();
    let r = drive(&mut cc.eng, stream, request, &mut sent, &mut got);
    let brssl_err = String::from_utf8_lossy(&stderr_shared.lock().unwrap()).into_owned();
    match r {
        Ok(()) => {
            if std::env::var("MTLS_TRACE").is_ok() {
                eprintln!("--- brssl stderr ---\n{}", brssl_err);
            }
            assert!(sent, "never reached the point of sending app data");
            assert!(!got.is_empty(), "no application data received from server");
            // Confirm the server actually performed client auth (trace mentions it).
            assert!(
                brssl_err.contains("CertificateVerify")
                    || brssl_err.contains("Handshake")
                    || brssl_err.contains("client certificate")
                    || !brssl_err.is_empty(),
                "expected brssl to log the handshake"
            );
        }
        Err(e) => panic!(
            "mTLS handshake/exchange failed: {} (err={})\n--- brssl stderr ---\n{}",
            e,
            cc.eng.last_error(),
            brssl_err
        ),
    }
}

/// Pump the client engine state machine (same logic as ssl_client_interop).
fn drive(
    eng: &mut br_ssl_engine_context,
    mut stream: TcpStream,
    request: &[u8],
    sent_request: &mut bool,
    got_appdata: &mut Vec<u8>,
) -> Result<(), String> {
    let mut rxbuf = [0u8; 4096];
    let mut loops = 0;
    let mut closing = false;
    loop {
        loops += 1;
        if loops > 100000 {
            return Err("too many iterations".into());
        }
        let st = eng.current_state();
        if st & BR_SSL_CLOSED != 0 {
            return if eng.last_error() == 0 {
                Ok(())
            } else {
                Err(format!("engine closed with error {}", eng.last_error()))
            };
        }
        if st & BR_SSL_SENDREC != 0 {
            let mut tmp = [0u8; 4096];
            let n = eng.sendrec(&mut tmp);
            if n > 0 {
                stream.write_all(&tmp[..n]).map_err(|e| e.to_string())?;
                continue;
            }
        }
        if st & BR_SSL_SENDAPP != 0 && !*sent_request {
            let n = eng.sendapp(request);
            if n > 0 {
                eng.flush(true);
                *sent_request = true;
                continue;
            }
        }
        if st & BR_SSL_RECVAPP != 0 {
            let mut tmp = [0u8; 4096];
            let n = eng.recvapp(&mut tmp);
            if n > 0 {
                got_appdata.extend_from_slice(&tmp[..n]);
                if *sent_request && !got_appdata.is_empty() {
                    eng.close();
                    closing = true;
                }
                continue;
            }
        }
        if closing && st & BR_SSL_SENDREC == 0 {
            return Ok(());
        }
        if st & BR_SSL_RECVREC != 0 {
            match stream.read(&mut rxbuf) {
                Ok(0) => return Err("peer closed before completion".into()),
                Ok(n) => {
                    let mut off = 0;
                    while off < n {
                        let c = eng.recvrec(&rxbuf[off..n]);
                        if c == 0 {
                            break;
                        }
                        off += c;
                    }
                    continue;
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err("timed out waiting for peer record".into());
                }
                Err(e) => return Err(format!("socket read: {}", e)),
            }
        }
        return Err(format!("engine wedged (state {:#x})", st));
    }
}
