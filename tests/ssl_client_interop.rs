//! Live TLS 1.2 interoperability: drive the Rust SSL *client* engine through a
//! full handshake against the upstream C `brssl server`, then exchange a tiny
//! HTTP request/response.
//!
//! The test is skipped (passes trivially) if the `brssl` binary or the sample
//! certificates are not present, so it never breaks a checkout that lacks the
//! upstream build tree. Point `BRSSL_DIR` at a built BearSSL checkout to run it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bearssl::ssl::*;
use bearssl::x509::{br_x509_pkey, br_x509_trust_anchor, BR_X509_TA_CA};

// ---- trust anchor (RSA root) from BearSSL samples/client_basic.c ------------

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

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rust_client_vs_brssl_server_rsa() {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let cert = dir.join("samples/cert-ee-rsa.pem");
    let key = dir.join("samples/key-ee-rsa.pem");
    let ica = dir.join("samples/cert-ica-rsa.pem");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }
    // Combine EE + ICA into one chain file so the server presents the full
    // chain up to (but excluding) the trusted root.
    let chain_path = std::env::temp_dir().join("bearssl_rs_chain.pem");
    {
        let mut c = std::fs::read(&cert).unwrap();
        if let Ok(mut i) = std::fs::read(&ica) {
            c.append(&mut i);
        }
        std::fs::write(&chain_path, &c).unwrap();
    }

    // Pick a free port.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    // Force the RSA-with-AES-128-GCM suite (we want a deterministic, supported
    // key exchange) using TLS 1.2 only.
    run_client_vs_brssl(&brssl, &chain_path, &key, port, "ECDHE_RSA_WITH_AES_128_GCM_SHA256");
}

#[test]
fn rust_client_vs_brssl_server_chapol() {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let cert = dir.join("samples/cert-ee-rsa.pem");
    let key = dir.join("samples/key-ee-rsa.pem");
    let ica = dir.join("samples/cert-ica-rsa.pem");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }
    let chain_path = std::env::temp_dir().join("bearssl_rs_chain_cp.pem");
    {
        let mut c = std::fs::read(&cert).unwrap();
        if let Ok(mut i) = std::fs::read(&ica) {
            c.append(&mut i);
        }
        std::fs::write(&chain_path, &c).unwrap();
    }
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    run_client_vs_brssl(
        &brssl,
        &chain_path,
        &key,
        port,
        "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    );
}

/// Spawn `brssl server` on `port` with the given suite, feeding it a line on
/// stdin (which it relays to the client) and capturing its stderr. Returns the
/// connected `TcpStream`, the shared stderr buffer, and the process guard.
fn spawn_brssl_server(
    brssl: &std::path::Path,
    chain_path: &std::path::Path,
    key: &std::path::Path,
    port: u16,
    cs: &str,
) -> (TcpStream, std::sync::Arc<std::sync::Mutex<Vec<u8>>>, ServerGuard) {
    // Force a single TLS 1.2 suite for a deterministic handshake. We do NOT pass
    // `-q`, and we capture stderr so a failed handshake prints brssl's own abort
    // reason / alert.
    let mut child = Command::new(brssl)
        .arg("server")
        .args(["-p", &port.to_string()])
        .args(["-cert", chain_path.to_str().unwrap()])
        .args(["-key", key.to_str().unwrap()])
        .args(["-vmin", "tls1.2", "-vmax", "tls1.2"])
        .args(["-cs", cs])
        .args(["-trace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn brssl server");
    // Feed the server a line on stdin: the brssl `server` command relays its
    // stdin to the connected client as application data, so this is what our
    // client will read back after sending its request.
    if let Some(mut si) = child.stdin.take() {
        std::thread::spawn(move || {
            // Small delay so the line is sent only once a peer is connected.
            std::thread::sleep(Duration::from_millis(600));
            let _ = si.write_all(b"hello from brssl server\n");
            let _ = si.flush();
            // Keep the handle alive so stdin is not closed (which would make the
            // server tear down the connection).
            std::thread::sleep(Duration::from_secs(8));
            drop(si);
        });
    }
    // Drain brssl's stderr on a background thread into a shared buffer so we can
    // print it on failure (brssl logs the exact alert / abort reason there).
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    if let Some(mut se) = child.stderr.take() {
        let buf = stderr_buf.clone();
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
    let guard = ServerGuard(child);

    // Give the server a moment to bind.
    std::thread::sleep(Duration::from_millis(300));

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    (stream, stderr_buf, guard)
}

#[test]
fn rust_client_vs_brssl_server_cbc() {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let cert = dir.join("samples/cert-ee-rsa.pem");
    let key = dir.join("samples/key-ee-rsa.pem");
    let ica = dir.join("samples/cert-ica-rsa.pem");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }
    let chain_path = std::env::temp_dir().join("bearssl_rs_chain_cbc.pem");
    {
        let mut c = std::fs::read(&cert).unwrap();
        if let Ok(mut i) = std::fs::read(&ica) {
            c.append(&mut i);
        }
        std::fs::write(&chain_path, &c).unwrap();
    }
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    // AES-128-CBC with SHA-256 MAC over ECDHE-RSA: exercises explicit-IV CBC.
    run_client_vs_brssl(
        &brssl,
        &chain_path,
        &key,
        port,
        "ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    );
}

fn run_client_vs_brssl(brssl: &std::path::Path, chain_path: &std::path::Path, key: &std::path::Path, port: u16, cs: &str) {
    let (stream, stderr_buf, _guard) = spawn_brssl_server(brssl, chain_path, key, port, cs);

    let mut cc = br_ssl_client_context::init_full(trust_anchors());
    assert!(cc.reset(Some("localhost"), false), "client reset failed");

    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    let mut sent_request = false;
    let mut got_appdata = Vec::new();

    let result = drive(&mut cc.eng, stream, request, &mut sent_request, &mut got_appdata);
    let brssl_err = String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned();
    match result {
        Ok(()) => {
            assert!(sent_request, "never reached the point of sending app data");
            assert!(
                !got_appdata.is_empty(),
                "no application data received from server"
            );
        }
        Err(e) => panic!(
            "handshake/exchange failed: {} (err={})\n--- brssl stderr ---\n{}",
            e,
            cc.eng.last_error(),
            brssl_err
        ),
    }
}

/// Same handshake + exchange, but driven through the `br_sslio_context`
/// blocking I/O convenience wrapper (the port of `ssl_io.c`) instead of the
/// hand-rolled `drive` state pump.
#[test]
fn rust_client_sslio_vs_brssl_server_rsa() {
    let dir = match brssl_dir() {
        Some(d) => d,
        None => {
            eprintln!("skipping: brssl build not found (set BRSSL_DIR)");
            return;
        }
    };
    let brssl = dir.join("build/brssl");
    let cert = dir.join("samples/cert-ee-rsa.pem");
    let key = dir.join("samples/key-ee-rsa.pem");
    let ica = dir.join("samples/cert-ica-rsa.pem");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: sample certs not found");
        return;
    }
    let chain_path = std::env::temp_dir().join("bearssl_rs_chain_io.pem");
    {
        let mut c = std::fs::read(&cert).unwrap();
        if let Ok(mut i) = std::fs::read(&ica) {
            c.append(&mut i);
        }
        std::fs::write(&chain_path, &c).unwrap();
    }
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (stream, stderr_buf, _guard) =
        spawn_brssl_server(&brssl, &chain_path, &key, port, "ECDHE_RSA_WITH_AES_128_GCM_SHA256");

    let mut cc = br_ssl_client_context::init_full(trust_anchors());
    assert!(cc.reset(Some("localhost"), false), "client reset failed");

    // The transport closures bridge the engine to the TcpStream. They follow the
    // C `low_read`/`low_write` convention: return the byte count, or `< 0` on a
    // hard error (a timeout is treated as a fatal error so the test cannot hang).
    let read_stream = stream.try_clone().unwrap();
    let write_stream = stream;
    let low_read = {
        let mut s = read_stream;
        Box::new(move |buf: &mut [u8]| -> LowResult {
            match s.read(buf) {
                Ok(0) => -1,
                Ok(n) => n as i32,
                Err(_) => -1,
            }
        }) as Box<LowRead>
    };
    let low_write = {
        let mut s = write_stream;
        Box::new(move |buf: &[u8]| -> LowResult {
            match s.write(buf) {
                Ok(0) => -1,
                Ok(n) => n as i32,
                Err(_) => -1,
            }
        }) as Box<LowWrite>
    };

    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    let mut got = [0u8; 256];
    let (wres, rlen) = {
        let mut io = br_sslio_context::new(&mut cc.eng, low_read, low_write);
        let wres = io.write_all(request);
        let _ = io.flush();
        // Read back the server's relayed line.
        let rlen = io.read(&mut got);
        (wres, rlen)
    };
    let brssl_err = String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned();
    assert!(
        wres == 0,
        "sslio write_all failed (err={})\n--- brssl stderr ---\n{}",
        cc.eng.last_error(),
        brssl_err
    );
    assert!(
        rlen > 0,
        "sslio read returned {} (err={})\n--- brssl stderr ---\n{}",
        rlen,
        cc.eng.last_error(),
        brssl_err
    );
}

/// Pump the engine state machine over a TCP stream.
fn drive(
    eng: &mut br_ssl_engine_context,
    mut stream: TcpStream,
    request: &[u8],
    sent_request: &mut bool,
    got_appdata: &mut Vec<u8>,
) -> Result<(), String> {
    let mut rxbuf = [0u8; 4096];
    let mut loops = 0;
    // Set once we have a full exchange (request sent + response received) and
    // have asked the engine to close: at that point we flush our own
    // close_notify but do not block waiting for the peer's, since RFC 5246
    // allows the peer to drop the connection without waiting for it.
    let mut closing = false;
    loop {
        loops += 1;
        if loops > 100000 {
            return Err("too many iterations".into());
        }
        let st = eng.current_state();
        if std::env::var("DRIVE_TRACE").is_ok() {
            eprintln!("[drive] loop={} state={:#x} sent={} got={}", loops, st, sent_request, got_appdata.len());
        }
        if st & BR_SSL_CLOSED != 0 {
            if eng.last_error() == 0 {
                return Ok(());
            }
            return Err(format!("engine closed with error {}", eng.last_error()));
        }

        // 1. Flush any outgoing records to the socket.
        if st & BR_SSL_SENDREC != 0 {
            let mut tmp = [0u8; 4096];
            let n = eng.sendrec(&mut tmp);
            if n > 0 {
                stream.write_all(&tmp[..n]).map_err(|e| e.to_string())?;
                continue;
            }
        }

        // 2. If the handshake is done and we have not yet sent our request, do so.
        if st & BR_SSL_SENDAPP != 0 && !*sent_request {
            let n = eng.sendapp(request);
            if n > 0 {
                eng.flush(true);
                *sent_request = true;
                continue;
            }
        }

        // 3. Drain received application data.
        if st & BR_SSL_RECVAPP != 0 {
            let mut tmp = [0u8; 4096];
            let n = eng.recvapp(&mut tmp);
            if n > 0 {
                got_appdata.extend_from_slice(&tmp[..n]);
                // Once we received a response after sending the request, the
                // exchange is complete: initiate a clean close.
                if *sent_request && !got_appdata.is_empty() {
                    eng.close();
                    closing = true;
                }
                continue;
            }
        }

        // If we have initiated a clean close and there are no more records to
        // send (our close_notify is on the wire), the exchange succeeded; do
        // not block waiting for the peer's close_notify.
        if closing && st & BR_SSL_SENDREC == 0 {
            return Ok(());
        }

        // 4. Feed transport bytes from the socket into the engine. A blocking
        // read with a timeout: any real timeout / EOF is a hard failure (the
        // engine is genuinely waiting on the peer, so there is nothing else to
        // do), which keeps `cargo test` from hanging.
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

        // Nothing actionable; the engine produced no work and wants no input.
        return Err(format!("engine wedged (state {:#x})", st));
    }
}
