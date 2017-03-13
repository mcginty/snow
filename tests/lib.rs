#![allow(non_snake_case)]
extern crate snow;
extern crate rustc_serialize;

mod vectors;

use snow::*;
use snow::params::*;

struct RandomInc {
    next_byte: u8
}

impl Default for RandomInc {

    fn default() -> RandomInc {
        RandomInc {next_byte: 0}
    }
}

impl Random for RandomInc {

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for count in 0..out.len() {
            out[count] = self.next_byte;
            if self.next_byte == 255 {
                self.next_byte = 0;
            }
            else {
                self.next_byte += 1;
            }
        }
    }
}

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}

#[test]
fn test_protocol_name() {

    let protocol_spec: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    assert_eq!(protocol_spec.base, BaseChoice::Noise);
    assert_eq!(protocol_spec.handshake, HandshakePattern::NK);
    assert_eq!(protocol_spec.cipher, CipherChoice::ChaChaPoly);
    assert_eq!(protocol_spec.hash, HashChoice::Blake2s);

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly_BLAKE2X".parse();
    if let Ok(_) = protocol_spec {
        panic!("invalid protocol was parsed inaccurately");
    }

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly".parse();
    if let Ok(_) = protocol_spec {
        panic!("invalid protocol was parsed inaccurately");
    }
}


#[test]
fn test_noise_session_transition_change() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params).build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    assert!(h_i.is_handshake_finished());
    assert!(h_r.is_handshake_finished());
    let _ = h_i.into_transport_mode().unwrap();
    let _ = h_r.into_transport_mode().unwrap();
}

