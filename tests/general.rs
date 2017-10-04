#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]
#![allow(non_snake_case)]
extern crate hex;
extern crate snow;

use hex::{FromHex, ToHex};
use snow::{NoiseBuilder, CryptoResolver, DefaultResolver};
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

fn get_inc_key(start: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = start + i as u8;
    }
    k
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
    if protocol_spec.is_ok() {
        panic!("invalid protocol was parsed inaccurately");
    }

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly".parse();
    if protocol_spec.is_ok() {
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
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
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
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_Npsk0_expected_value() {
    let params: NoiseParams = "Noise_Npsk0_25519_AESGCM_SHA256".parse().unwrap();
    let mut static_r: Dh25519 = Default::default();
    static_r.set(&get_inc_key(0));
    let mut h_i = NoiseBuilder::new(params)
        .remote_public_key(static_r.pubkey())
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator().unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9").unwrap();

    println!("\nreality:  {}", (&buf[..len]).to_hex());
    println!("expected: {}", (&expected).to_hex());
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn test_Xpsk0_expected_value() {
    let params: NoiseParams = "Noise_Xpsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();
    static_i.set(&get_inc_key(0));
    static_r.set(&get_inc_key(32));
    let mut h_i = NoiseBuilder::new(params)
        .local_private_key(static_i.privkey())
        .remote_public_key(static_r.pubkey())
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(64))
        .build_initiator().unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 96);

    let expected = Vec::<u8>::from_hex("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad51eef529db0dd9127d4aa59a9183e118337d75a4e55e7e00f85c3d20ede536dd0112eec8c3b2a514018a90ab685b027dd24aa0c70b0c0f00524cc23785028b9").unwrap();

    println!("\nreality:  {}", (&buf[..len]).to_hex());
    println!("expected: {}", (&expected).to_hex());
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn test_XXpsk0_expected_value() {
    let params: NoiseParams = "Noise_XXpsk0_25519_AESGCM_SHA256".parse().unwrap();
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();
    static_i.set(&get_inc_key(0));
    static_r.set(&get_inc_key(1));
    let mut h_i = NoiseBuilder::new(params.clone())
        .local_private_key(static_i.privkey())
        .remote_public_key(static_r.pubkey())
        .prologue(&[1u8, 2, 3])
        .psk(0, &get_inc_key(4))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params)
        .local_private_key(static_r.privkey())
        .remote_public_key(static_i.pubkey())
        .prologue(&[1u8, 2, 3])
        .psk(0, &get_inc_key(4))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(33))
        .build_responder().unwrap();

    let mut buf = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    let len = h_i.write_message(b"abc", &mut buf).unwrap();
    assert_eq!(len, 51);
    let len = h_r.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(&buf2[..len], b"abc");

    let len = h_r.write_message(b"defg", &mut buf).unwrap();
    assert_eq!(len, 100);
    let len = h_i.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(&buf2[..len], b"defg");

    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 64);
    let len = h_r.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(len, 0);

    let expected = Vec::<u8>::from_hex("1b6d7cc3b13bd02217f9cdb98c50870db96281193dca4df570bf6230a603b686fd90d2914c7e797d9276ef8fb34b0c9d87faa048ce4bc7e7af21b6a450352275").unwrap();
    println!("\nreality:  {}", (&buf[..64]).to_hex());
    println!("expected: {}", (&expected).to_hex());
    assert_eq!(&buf[..64], &expected[..]);
}

#[test]
fn test_NNpsk0_sanity_session() {
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
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_XXpsk1_sanity_session() {
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
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_i.write_message(b"hij", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_rekey() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params).build_responder().unwrap();

    assert!(h_i.rekey(None, None).is_err());

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    h_i.rekey(Some(&[1u8; 32]), Some(&[2u8; 32])).unwrap();
    h_r.rekey(Some(&[1u8; 32]), Some(&[2u8; 32])).unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    let len = h_r.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
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

#[test]
fn test_set_nonce() {
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

    init.write_message(&[0u8; 1024], &mut buffer_init).unwrap(); // skip to bump the nonce up
    init.write_message(&[0u8; 1024], &mut buffer_init).unwrap(); // skip to bump the nonce up
    init.write_message(&[0u8; 1024], &mut buffer_init).unwrap(); // skip to bump the nonce up
    let outbound_nonce = init.sending_nonce().unwrap();
    let len = init.write_message(&[0u8; 1024], &mut buffer_init).unwrap();


    resp.set_receiving_nonce(outbound_nonce).unwrap();
    resp.read_message(&buffer_init[..len], &mut buffer_resp).unwrap();

}
