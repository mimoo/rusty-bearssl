fn main(){
  let iec = bearssl::ec::br_ec_get_default();
  println!("supported_curves = {:#x} ({} bits set)", iec.supported_curves, iec.supported_curves.count_ones());
}
