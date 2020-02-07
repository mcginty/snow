#[macro_use] extern crate honggfuzz;
extern crate snow;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
             if let Ok(s) = String::from_utf8(data.to_vec()){
                if let Ok(p) = s.parse() {
                    let builder = snow::Builder::new(p);
                    let _  = builder.build_initiator();
                }
            }
        });
    }
}
