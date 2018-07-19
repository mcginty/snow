#[macro_use] extern crate honggfuzz;
#[macro_use] extern crate lazy_static;
extern crate snow;

use snow::params::NoiseParams;

static SECRET: &'static [u8] = b"i don't care for fidget spinners";
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            let builder = snow::Builder::new(PARAMS.clone());
            let mut noise = builder.build_responder().unwrap();
            let mut out_buf = [0u8; 64000];

            let _ = noise.read_message(data, &mut out_buf);
        });
    }
}