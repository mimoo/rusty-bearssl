//! Live TLS 1.2 interoperability: drive the Rust SSL *server* engine through a
//! full handshake against the upstream C `brssl client`, then exchange a tiny
//! request/response.
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
use bearssl::x509::{br_skey, br_skey_decoder_init, br_skey_decoder_push};

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
        // The sink closure must outlive each push; rebuild it per iteration.
        let mut sink = move |chunk: &[u8]| {
            sink_cur.borrow_mut().extend_from_slice(chunk);
        };
        // SAFETY of lifetimes: setdest borrows for 'a tied to ctx; we clear it
        // before the closure drops by setting dest to None after each push.
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
            BR_PEM_END_OBJ => {
                out.push((name.clone(), cur.borrow().clone()));
            }
            BR_PEM_ERROR => break,
            _ => {}
        }
        br_pem_decoder_setdest(&mut ctx, None);
        let _ = &mut sink; // keep sink alive until here
    }
    out
}

/// Read the certificate chain (all CERTIFICATE objects) from a PEM file.
fn read_chain(path: &std::path::Path) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).unwrap();
    pem_objects(&data)
        .into_iter()
        .filter(|(n, _)| n.contains("CERTIFICATE"))
        .map(|(_, d)| d)
        .collect()
}

/// Decode the RSA private key from a PEM file into the parts the server needs.
fn read_rsa_key(path: &std::path::Path) -> RsaPrivateKeyParts {
    let data = std::fs::read(path).unwrap();
    let objs = pem_objects(&data);
    // The first (only) object is the private key DER.
    let der = &objs[0].1;
    let mut dc = br_skey_decoder_init();
    br_skey_decoder_push(&mut dc, der);
    match dc.key() {
        br_skey::RSA {
            n_bitlen,
            p,
            q,
            dp,
            dq,
            iq,
        } => RsaPrivateKeyParts {
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
fn rust_server_vs_brssl_client_rsa() {
    run_server_vs_brssl_client("ECDHE_RSA_WITH_AES_128_GCM_SHA256");
}

#[test]
fn rust_server_vs_brssl_client_cbc() {
    run_server_vs_brssl_client("ECDHE_RSA_WITH_AES_128_CBC_SHA256");
}

#[test]
fn rust_server_vs_brssl_client_chapol() {
    run_server_vs_brssl_client("ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
}

#[test]
fn rust_server_vs_brssl_client_rsa_keyx() {
    run_server_vs_brssl_client("RSA_WITH_AES_128_GCM_SHA256");
}

fn run_server_vs_brssl_client(cs: &str) {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let cert = dir.join("samples/cert-ee-rsa.pem");
    let ica = dir.join("samples/cert-ica-rsa.pem");
    let key = dir.join("samples/key-ee-rsa.pem");
    let root = dir.join("samples/cert-root-rsa.pem");
    if !cert.exists() || !key.exists() || !root.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }

    // Build the server certificate chain: EE + ICA (root is the brssl client's
    // trust anchor, supplied via -CA).
    let mut chain = read_chain(&cert);
    chain.extend(read_chain(&ica));
    let sk = read_rsa_key(&key);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Spawn the brssl client; it connects to our server, sends one line on its
    // stdin to us, and prints what it receives. We give it the root CA so it
    // validates our chain.
    let mut child = Command::new(&brssl)
        .arg("client")
        .arg(format!("127.0.0.1:{}", port))
        .args(["-CA", root.to_str().unwrap()])
        // The sample EE certificate is issued for "localhost"; tell the client
        // to expect that name (and send it as SNI) rather than 127.0.0.1.
        .args(["-sni", "localhost"])
        .args(["-vmin", "tls1.2", "-vmax", "tls1.2"])
        .args(["-cs", cs])
        .args(["-trace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn brssl client");
    if let Some(mut si) = child.stdin.take() {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            let _ = si.write_all(b"hello from rust server test\n");
            let _ = si.flush();
            std::thread::sleep(Duration::from_secs(8));
            drop(si);
        });
    }
    let stderr_pipe = child.stderr.take();
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    if let Some(mut se) = stderr_pipe {
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

    // Accept the incoming connection (with a timeout so we never hang).
    listener
        .set_nonblocking(false)
        .unwrap();
    let (stream, _addr) = {
        // Accept can block; use a short-lived thread-based timeout via a
        // dedicated accept with the listener's default blocking mode but bounded
        // by the overall test runtime. brssl connects within ~500ms.
        listener.accept().expect("accept brssl client")
    };
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut sc = br_ssl_server_context::init_full_rsa(chain, sk);
    assert!(sc.reset(), "server reset failed");

    let response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    let mut got = Vec::new();
    let r = drive_server(&mut sc.eng, stream, response, &mut got);
    let brssl_err = String::from_utf8_lossy(&stderr_shared.lock().unwrap()).into_owned();
    match r {
        Ok(()) => {
            assert!(!got.is_empty(), "server received no application data");
        }
        Err(e) => panic!(
            "server handshake/exchange failed: {} (err={})\n--- brssl stderr ---\n{}",
            e,
            sc.eng.last_error(),
            brssl_err
        ),
    }
}

/// Drive the server engine: complete the handshake, read the client's request,
/// send a response, then close.
fn drive_server(
    eng: &mut br_ssl_engine_context,
    mut stream: TcpStream,
    response: &[u8],
    got: &mut Vec<u8>,
) -> Result<(), String> {
    let mut rxbuf = [0u8; 4096];
    let mut sent = false;
    let mut closing = false;
    let mut loops = 0;
    loop {
        loops += 1;
        if loops > 100000 {
            return Err("too many iterations".into());
        }
        let st = eng.current_state();
        if std::env::var("DRIVE_TRACE").is_ok() {
            eprintln!("[srv] loop={} state={:#x} sent={} got={}", loops, st, sent, got.len());
        }
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

        // Drain received application data (the client's request).
        if st & BR_SSL_RECVAPP != 0 {
            let mut tmp = [0u8; 4096];
            let n = eng.recvapp(&mut tmp);
            if n > 0 {
                got.extend_from_slice(&tmp[..n]);
                continue;
            }
        }

        // Once we have the request, send our response, then close.
        if st & BR_SSL_SENDAPP != 0 && !got.is_empty() && !sent {
            let n = eng.sendapp(response);
            if n > 0 {
                eng.flush(true);
                sent = true;
                continue;
            }
        }
        if sent && !closing {
            eng.close();
            closing = true;
            continue;
        }
        if closing && st & BR_SSL_SENDREC == 0 {
            return Ok(());
        }

        if st & BR_SSL_RECVREC != 0 {
            match stream.read(&mut rxbuf) {
                Ok(0) => {
                    // Client closed; if we already got the request, that's fine.
                    return if !got.is_empty() {
                        Ok(())
                    } else {
                        Err("peer closed before request".into())
                    };
                }
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
                    return Err("timed out waiting for client record".into());
                }
                Err(e) => return Err(format!("socket read: {}", e)),
            }
        }
        return Err(format!("server engine wedged (state {:#x})", st));
    }
}
