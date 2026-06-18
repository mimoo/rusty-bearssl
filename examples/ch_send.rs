use std::io::{Read,Write};
use std::net::TcpStream;
use std::time::Duration;
fn main(){
  let mut out=[0u8;4096];
  // Reuse the exact ClientHello bytes from ch_dbg by reconstructing via engine.
  use bearssl::ssl::*;
  use bearssl::x509::{br_x509_pkey, br_x509_trust_anchor, BR_X509_TA_CA};
  static DN:[u8;4]=[0x30,0x02,0x05,0x00];
  let tas: &'static [br_x509_trust_anchor<'static>] = Box::leak(vec![br_x509_trust_anchor{dn:&DN,flags:BR_X509_TA_CA,pkey:br_x509_pkey::RSA{n:vec![1;256],e:vec![1,0,1]}}].into_boxed_slice());
  let mut cc = br_ssl_client_context::init_full(tas);
  cc.reset(Some("localhost"), false);
  let n=cc.eng.sendrec(&mut out);
  let mut s=TcpStream::connect(("127.0.0.1",14433u16)).unwrap();
  s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
  s.write_all(&out[..n]).unwrap();
  println!("sent {} bytes", n);
  let mut buf=[0u8;4096];
  match s.read(&mut buf){ Ok(m)=>{println!("read {} bytes:",m); for b in &buf[..m.min(48)]{print!("{:02x} ",b);} println!();}, Err(e)=>println!("read err {}",e) }
}
