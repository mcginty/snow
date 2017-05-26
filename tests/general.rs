#![allow(non_snake_case)]
extern crate hex;
extern crate snow;

use hex::{FromHex, ToHex};
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

#[allow(unused)]
struct TestResolver {
    next_byte: u8,
    parent: DefaultResolver,
}

#[allow(unused)]
impl TestResolver {
    pub fn new(next_byte: u8) -> Self {
        TestResolver{ next_byte: next_byte, parent: DefaultResolver }
    }

    pub fn next_byte(&mut self, next_byte: u8) {
        self.next_byte = next_byte;
    }
}

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<Random>> {
        let mut rng = RandomInc::default();
        rng.next_byte = self.next_byte;
        Some(Box::new(rng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<Dh>> {
        self.parent.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<Hash>> {
        self.parent.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<Cipher>> {
        self.parent.resolve_cipher(choice)
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
    assert_eq!(protocol_spec.handshake.pattern, HandshakePattern::NK);
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
    let mut h_i = NoiseBuilder::new(params.clone()).build_initiator().unwrap();
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
    let mut h_i = NoiseBuilder::new(params.clone()).build_initiator().unwrap();
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
fn test_n_psk0_expected_value() {
    let params: NoiseParams = "Noise_Npsk0_25519_AESGCM_SHA256".parse().unwrap();
    let mut static_r: Dh25519 = Default::default();
    static_r.set(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
    let mut h_i = NoiseBuilder::new(params)
        .remote_public_key(static_r.pubkey())
        .psk(0, &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 , 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
        .fixed_ephemeral_key_for_testing_only(&[32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63])
        .build_initiator().unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert!(len == 48);

    let expected = Vec::<u8>::from_hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9").unwrap();

    println!("\nreality:  {}", (&buf[..len]).to_hex());
    println!("expected: {}", (&expected).to_hex());
    assert!(&buf[..len] == &expected[..]);
}

#[test]
fn test_psk0_sanity_session() {
    let params: NoiseParams = "Noise_NNpsk0_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params.clone())
        .psk(0, &[32u8; 32])
        .build_initiator()
        .unwrap();
    let mut h_r = NoiseBuilder::new(params)
        .psk(0, &[32u8; 32])
        .build_responder()
        .unwrap();

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
fn test_XX_psk1_sanity_session() {
    let params: NoiseParams = "Noise_XXpsk1_25519_AESGCM_SHA256".parse().unwrap();
    let b_i = NoiseBuilder::new(params.clone());
    let b_r = NoiseBuilder::new(params);
    let static_i = b_i.generate_private_key().unwrap();
    let static_r = b_r.generate_private_key().unwrap();
    let mut static_i_dh: Dh25519 = Default::default();
    let mut static_r_dh: Dh25519 = Default::default();
    static_i_dh.set(&static_i);
    static_r_dh.set(&static_r);
    let mut h_i = b_i
        .psk(1, &[32u8; 32])
        .local_private_key(&static_i)
        .remote_public_key(static_r_dh.pubkey())
        .build_initiator()
        .unwrap();
    let mut h_r = b_r
        .psk(1, &[32u8; 32])
        .local_private_key(&static_r)
        .remote_public_key(static_i_dh.pubkey())
        .build_responder()
        .unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_i.write_message("hij".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message("hack the planet".as_bytes(), &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert!(&buffer_out[..len] == "hack the planet".as_bytes());
}

#[test]
fn test_rekey() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params.clone()).build_initiator().unwrap();
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
    let resp_builder = NoiseBuilder::new(params.clone());
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

