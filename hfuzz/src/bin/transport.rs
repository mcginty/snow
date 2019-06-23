#[macro_use] extern crate honggfuzz;
#[macro_use] extern crate lazy_static;
extern crate snow;

use snow::params::NoiseParams;

static SECRET: &'static [u8] = b"i don't care for fidget spinners";
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

fn main() {
    let mut out_buf = vec![0u8; 128 * 1024 * 1024];
    let mut initiator = snow::Builder::new(PARAMS.clone()).build_initiator().unwrap();
    let mut responder = snow::Builder::new(PARAMS.clone()).build_responder().unwrap();

    let len = initiator.write_message(&[], &mut out_buf).unwrap();
    responder.read_message(&out_buf[..len], &mut []);
    let len = responder.write_message(&[], &mut out_buf).unwrap();
    initiator.read_message(&out_buf[..len], &mut []);
    
    let mut responder = responder.into_transport_mode().unwrap();
    let mut initiator = initiator.into_transport_mode().unwrap();

    loop {
        fuzz!(|data: &[u8]| {
            let _ = initiator.write_message(data, &mut out_buf);
            let _ = initiator.read_message(data, &mut out_buf);
        });
    }
}
