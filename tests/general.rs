#![allow(non_snake_case)]
extern crate hex;
extern crate snow;

use snow::*;
use snow::params::*;
use snow::types::*;
use snow::wrappers::crypto_wrapper::Dh25519;

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

#[test]
fn test_sanity_session() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params).build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message("hack the planet".as_bytes(), &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert!(&buffer_out[..len] == "hack the planet".as_bytes());
}

#[test]
fn test_rekey() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params).build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params).build_responder().unwrap();

    assert!(h_i.rekey(None, None).is_err());

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message("hack the planet".as_bytes(), &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert!(&buffer_out[..len] == "hack the planet".as_bytes());

    h_i.rekey(Some(&[1u8; 32]), Some(&[2u8; 32])).unwrap();
    h_r.rekey(Some(&[1u8; 32]), Some(&[2u8; 32])).unwrap();

    let len = h_i.write_message("hack the planet".as_bytes(), &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert!(&buffer_out[..len] == "hack the planet".as_bytes());

    let len = h_r.write_message("hack the planet".as_bytes(), &mut buffer_msg).unwrap();
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert!(&buffer_out[..len] == "hack the planet".as_bytes());
}

#[test]
fn test_handshake_message_exceeds_max_len() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params).build_initiator().unwrap();

    let mut buffer_out = [0u8; 65535*2];
    assert!(h_i.write_message(&[0u8; 65530], &mut buffer_out).is_err());
}

#[test]
fn test_handshake_message_undersized_output_buffer() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params).build_initiator().unwrap();

    let mut buffer_out = [0u8; 200];
    assert!(h_i.write_message(&[0u8; 400], &mut buffer_out).is_err());
}

#[test]
fn test_transport_message_exceeds_max_len() {
    let params: NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse().unwrap();
    let mut noise = NoiseBuilder::new(params).remote_public_key(&[0u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 65535*2];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    noise = noise.into_transport_mode().unwrap();
    assert!(noise.write_message(&[0u8; 65534], &mut buffer_out).is_err());
}

#[test]
fn test_transport_message_undersized_output_buffer() {
    let params: NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse().unwrap();
    let mut noise = NoiseBuilder::new(params).remote_public_key(&[0u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 200];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    noise = noise.into_transport_mode().unwrap();
    assert!(noise.write_message(&[0u8; 300], &mut buffer_out).is_err());
}

#[test]
fn test_oneway_initiator_enforcements() {
    let params: NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse().unwrap();
    let mut noise = NoiseBuilder::new(params).remote_public_key(&[0u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 1024];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    noise = noise.into_transport_mode().unwrap();
    assert!(noise.read_message(&[0u8; 1024], &mut buffer_out).is_err());
}

#[test]
fn test_oneway_responder_enforcements() {
    let params: NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse().unwrap();
    let resp_builder = NoiseBuilder::new(params);
    let rpk = resp_builder.generate_private_key().unwrap();
    let mut rk: Dh25519 = Dh25519::default();
    rk.set(&rpk);

    let mut resp = resp_builder.local_private_key(&rpk).build_responder().unwrap();
    let mut init = NoiseBuilder::new(params).remote_public_key(rk.pubkey()).build_initiator().unwrap();

    let mut buffer_resp = [0u8; 65535];
    let mut buffer_init = [0u8; 65535];
    let len = init.write_message(&[0u8; 0], &mut buffer_init).unwrap();
    resp.read_message(&buffer_init[..len], &mut buffer_resp).unwrap();
    init = init.into_transport_mode().unwrap();
    resp = resp.into_transport_mode().unwrap();

    assert!(init.read_message(&[0u8; 1024], &mut buffer_init).is_err());
    assert!(resp.write_message(&[0u8; 1024], &mut buffer_resp).is_err());
}

