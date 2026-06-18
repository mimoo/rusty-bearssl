use bearssl::ssl::*;
use bearssl::x509::{br_x509_pkey, br_x509_trust_anchor, BR_X509_TA_CA};
static DN:[u8;4]=[0x30,0x02,0x05,0x00];
fn main(){
  let tas: &'static [br_x509_trust_anchor<'static>] = Box::leak(vec![br_x509_trust_anchor{dn:&DN,flags:BR_X509_TA_CA,pkey:br_x509_pkey::RSA{n:vec![1;256],e:vec![1,0,1]}}].into_boxed_slice());
  let mut cc = br_ssl_client_context::init_full(tas);
  println!("reset ok={}", cc.reset(Some("localhost"), false));
  println!("err={}", cc.eng.last_error());
  let mut out=[0u8;4096];
  let n=cc.eng.sendrec(&mut out);
  println!("first sendrec n={}", n);
  if n>0 { for b in &out[..n.min(64)] { print!("{:02x} ", b);} println!(); }
  println!("state after={:#x}", cc.eng.current_state());
}
