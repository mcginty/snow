#![cfg(feature = "std")]
#![cfg(any(feature = "default-resolver-crypto", feature = "ring-accelerated"))]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::shadow_reuse)]
#![allow(non_snake_case)]

use hex::FromHex;
use snow::{
    resolvers::{CryptoResolver, DefaultResolver},
    Builder, Error,
};

use rand_core::{impls, CryptoRng, RngCore};
use snow::{params::*, types::*};
use x25519_dalek as x25519;

type TestResult = Result<(), Box<dyn core::error::Error>>;

#[derive(Default)]
struct CountingRng(u64);

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64()).expect("u32 should be plenty")
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CountingRng {}
impl Random for CountingRng {}

#[allow(clippy::cast_possible_truncation)]
fn get_inc_key(start: u8) -> [u8; 32] {
    let mut k = [0_u8; 32];
    for i in 0_u8..32 {
        k[usize::from(i)] = start + i;
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
        TestResolver { next_byte, parent: DefaultResolver }
    }

    pub fn next_byte(&mut self, next_byte: u8) {
        self.next_byte = next_byte;
    }
}

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        let rng = CountingRng(u64::from(self.next_byte));
        Some(Box::new(rng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.parent.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.parent.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.parent.resolve_cipher(choice)
    }
}

#[test]
fn test_protocol_name() -> TestResult {
    let protocol_spec: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse()?;

    assert_eq!(protocol_spec.base, BaseChoice::Noise);
    assert_eq!(protocol_spec.handshake.pattern, HandshakePattern::NK);
    assert_eq!(protocol_spec.cipher, CipherChoice::ChaChaPoly);
    assert_eq!(protocol_spec.hash, HashChoice::Blake2s);

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly_FAKE2X".parse();
    assert!(protocol_spec.is_err(), "invalid protocol was parsed inaccurately");

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly".parse();
    assert!(protocol_spec.is_err(), "invalid protocol was parsed inaccurately");
    Ok(())
}

#[test]
fn test_noise_state_change() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    assert!(h_i.is_handshake_finished());
    assert!(h_r.is_handshake_finished());
    let _ = h_i.into_transport_mode()?;
    let _ = h_r.into_transport_mode()?;
    Ok(())
}

#[test]
fn test_sanity_chachapoly_session() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_sanity_aesgcm_session() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_Npsk0_chachapoly_expected_value() -> TestResult {
    let params: NoiseParams = "Noise_Npsk0_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))?
        .psk(0, &get_inc_key(1))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()?;

    let mut buf = [0_u8; 200];
    let len = h_i.write_message(&[], &mut buf)?;
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254deb8a4f6190117dea09aad7546a4658c",
    )?;

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
    Ok(())
}

#[test]
fn test_Npsk0_aesgcm_expected_value() -> TestResult {
    let params: NoiseParams = "Noise_Npsk0_25519_AESGCM_SHA256".parse()?;
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))?
        .psk(0, &get_inc_key(1))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()?;

    let mut buf = [0_u8; 200];
    let len = h_i.write_message(&[], &mut buf)?;
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9",
    )?;

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
    Ok(())
}

#[test]
fn test_Npsk0_expected_value() -> TestResult {
    let params: NoiseParams = "Noise_Npsk0_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))?
        .psk(0, &get_inc_key(1))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()?;

    let mut buf = [0_u8; 200];
    let len = h_i.write_message(&[], &mut buf)?;
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254deb8a4f6190117dea09aad7546a4658c",
    )?;

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
    Ok(())
}

#[test]
fn test_Xpsk0_expected_value() -> TestResult {
    let params: NoiseParams = "Noise_Xpsk0_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params)
        .local_private_key(&get_inc_key(0))?
        .remote_public_key(&x25519::x25519(get_inc_key(32), x25519::X25519_BASEPOINT_BYTES))?
        .psk(0, &get_inc_key(1))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(64))
        .build_initiator()?;

    let mut buf = [0_u8; 200];
    let len = h_i.write_message(&[], &mut buf)?;
    assert_eq!(len, 96);

    let expected = Vec::<u8>::from_hex("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad51eef529db0dd9127d4aa59a9183e118337d75a4e55e7e00f85c3d20ede536dd0112eec8c3b2a514018a90ab685b027dd24aa0c70b0c0f00524cc23785028b9")?;

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
    Ok(())
}

#[test]
#[cfg(feature = "hfs")]
#[cfg(feature = "use-pqcrypto-kyber1024")]
fn test_NNhfs_sanity_session() -> TestResult {
    // Due to how PQClean is implemented, we cannot do deterministic testing of the protocol.
    // Instead, we will see if the protocol runs smoothly.
    let params: NoiseParams = "Noise_NNhfs_25519+Kyber1024_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 4096];
    let mut buffer_out = [0_u8; 4096];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_XXpsk0_expected_value() -> TestResult {
    let params: NoiseParams = "Noise_XXpsk0_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone())
        .local_private_key(&get_inc_key(0))?
        .remote_public_key(&x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES))?
        .prologue(&[1_u8, 2, 3])?
        .psk(0, &get_inc_key(4))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()?;
    let mut h_r = Builder::new(params)
        .local_private_key(&get_inc_key(1))?
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))?
        .prologue(&[1_u8, 2, 3])?
        .psk(0, &get_inc_key(4))?
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(33))
        .build_responder()?;

    let mut buf = [0_u8; 1024];
    let mut buf2 = [0_u8; 1024];

    let len = h_i.write_message(b"abc", &mut buf)?;
    assert_eq!(len, 51);
    let len = h_r.read_message(&buf[..len], &mut buf2)?;
    assert_eq!(&buf2[..len], b"abc");

    let len = h_r.write_message(b"defg", &mut buf)?;
    assert_eq!(len, 100);
    let len = h_i.read_message(&buf[..len], &mut buf2)?;
    assert_eq!(&buf2[..len], b"defg");

    let len = h_i.write_message(&[], &mut buf)?;
    assert_eq!(len, 64);
    let len = h_r.read_message(&buf[..len], &mut buf2)?;
    assert_eq!(len, 0);

    let expected = Vec::<u8>::from_hex("072b7bbd237ac602c4aa938db36998f31ca4750752d1758d59850c627d0bdbc51205592c3baa101b4a31f062695b7c1dbee99d5123fbd2ad03052078c570e028")?;
    println!("\nreality:  {}", hex::encode(&buf[..64]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..64], &expected[..]);
    Ok(())
}

#[test]
fn test_NNpsk0_sanity_session() -> TestResult {
    let params: NoiseParams = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).psk(0, &[32_u8; 32])?.build_initiator()?;
    let mut h_r = Builder::new(params).psk(0, &[32_u8; 32])?.build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_XXpsk3_sanity_session() -> TestResult {
    let params: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse()?;
    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);
    let static_i = b_i.generate_keypair()?;
    let static_r = b_r.generate_keypair()?;
    let mut h_i = b_i
        .psk(3, &[32_u8; 32])?
        .local_private_key(&static_i.private)?
        .remote_public_key(&static_r.public)?
        .build_initiator()?;
    let mut h_r = b_r
        .psk(3, &[32_u8; 32])?
        .local_private_key(&static_r.private)?
        .remote_public_key(&static_i.public)?
        .build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_i.write_message(b"hij", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_rekey() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    // test message initiator->responder before rekeying initiator
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey outgoing on initiator
    h_i.rekey_outgoing();
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    assert!(h_r.read_message(&buffer_msg[..len], &mut buffer_out).is_err());
    h_r.set_receiving_nonce(h_i.sending_nonce());

    // rekey incoming on responder
    h_r.rekey_incoming();
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey outgoing on responder
    h_r.rekey_outgoing();
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg)?;
    assert!(h_i.read_message(&buffer_msg[..len], &mut buffer_out).is_err());
    h_i.set_receiving_nonce(h_r.sending_nonce());

    // rekey incoming on initiator
    h_i.rekey_incoming();
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_rekey_manually() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];

    // Do a handshake, and transition to stateful transport mode.
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;
    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    // test sanity message initiator->responder before rekeying initiator
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey initiator-side initiator key to K1 without rekeying the responder,
    // expecting a decryption failure.
    //
    // The message *should* have failed to read, so we also force nonce re-sync.
    h_i.rekey_manually(Some(&[1_u8; 32]), None);
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    assert!(h_r.read_message(&buffer_msg[..len], &mut buffer_out).is_err());
    h_r.set_receiving_nonce(h_i.sending_nonce());

    // rekey responder-side responder key to K1, expecting a successful decryption.
    h_r.rekey_manually(Some(&[1_u8; 32]), None);
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey responder-side responder key to K1 without rekeying the initiator,
    // expecting a decryption failure.
    //
    // The message *should* have failed to read, so we also force nonce re-sync.
    h_r.rekey_manually(None, Some(&[1_u8; 32]));
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg)?;
    assert!(h_i.read_message(&buffer_msg[..len], &mut buffer_out).is_err());
    h_i.set_receiving_nonce(h_r.sending_nonce());

    // rekey intiator-side responder key to K1, expecting a successful decryption.
    h_i.rekey_manually(None, Some(&[1_u8; 32]));
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg)?;
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_handshake_message_exceeds_max_len() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params).build_initiator()?;

    let mut buffer_out = vec![0_u8; 65535 * 2].into_boxed_slice();
    assert!(h_i.write_message(&vec![0_u8; 65530].into_boxed_slice(), &mut buffer_out).is_err());
    Ok(())
}

#[test]
fn test_handshake_message_undersized_output_buffer() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params).build_initiator()?;

    let mut buffer_out = [0_u8; 200];
    assert!(h_i.write_message(&[0_u8; 400], &mut buffer_out).is_err());
    Ok(())
}

#[test]
fn test_handshake_message_receive_oversized_message() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = vec![0_u8; 100_000].into_boxed_slice();
    let mut buffer_out = vec![0_u8; 100_000].into_boxed_slice();
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    assert_eq!(Error::Input, h_r.read_message(&buffer_msg, &mut buffer_out).unwrap_err());
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let h_i = h_i.into_stateless_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(0, b"hack the planet", &mut buffer_msg)?;
    assert_eq!(Error::Input, h_r.read_message(&buffer_msg, &mut buffer_out).unwrap_err());
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"hack the planet", &mut buffer_msg)?;
    assert_eq!(Error::Input, h_i.read_message(0, &buffer_msg, &mut buffer_out).unwrap_err());
    let len = h_i.read_message(0, &buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");

    Ok(())
}

#[test]
fn test_transport_message_exceeds_max_len() -> TestResult {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse()?;
    let mut noise = Builder::new(params).remote_public_key(&[1_u8; 32])?.build_initiator()?;

    let mut buffer_out = vec![0_u8; 65535 * 2].into_boxed_slice();
    noise.write_message(&[0_u8; 0], &mut buffer_out)?;
    let mut noise = noise.into_transport_mode()?;
    assert!(noise.write_message(&vec![0_u8; 65534].into_boxed_slice(), &mut buffer_out).is_err());
    Ok(())
}

#[test]
fn test_transport_message_undersized_output_buffer() -> TestResult {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse()?;
    let mut noise = Builder::new(params).remote_public_key(&[1_u8; 32])?.build_initiator()?;

    let mut buffer_out = [0_u8; 200];
    noise.write_message(&[0_u8; 0], &mut buffer_out)?;
    let mut noise = noise.into_transport_mode()?;
    assert!(noise.write_message(&[0_u8; 300], &mut buffer_out).is_err());
    Ok(())
}

#[test]
fn test_oneway_initiator_enforcements() -> TestResult {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse()?;
    let mut noise = Builder::new(params).remote_public_key(&[1_u8; 32])?.build_initiator()?;

    let mut buffer_out = [0_u8; 1024];
    noise.write_message(&[0_u8; 0], &mut buffer_out)?;
    let mut noise = noise.into_transport_mode()?;
    assert!(noise.read_message(&[0_u8; 1024], &mut buffer_out).is_err());
    Ok(())
}

#[test]
fn test_oneway_responder_enforcements() -> TestResult {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse()?;
    let resp_builder = Builder::new(params.clone());
    let rpk = resp_builder.generate_keypair()?;

    let mut resp = resp_builder.local_private_key(&rpk.private)?.build_responder()?;
    let mut init = Builder::new(params).remote_public_key(&rpk.public)?.build_initiator()?;

    let mut buffer_resp = vec![0_u8; 65535].into_boxed_slice();
    let mut buffer_init = vec![0_u8; 65535].into_boxed_slice();
    let len = init.write_message(&[0_u8; 0], &mut buffer_init)?;
    resp.read_message(&buffer_init[..len], &mut buffer_resp)?;
    let mut init = init.into_transport_mode()?;
    let mut resp = resp.into_transport_mode()?;

    assert!(init.read_message(&[0_u8; 1024], &mut buffer_init).is_err());
    assert!(resp.write_message(&[0_u8; 1024], &mut buffer_resp).is_err());
    Ok(())
}

#[test]
fn test_buffer_issues() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 2];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_err());
    Ok(())
}

#[test]
fn test_read_buffer_issues() -> TestResult {
    let params: NoiseParams = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse()?;

    let builder_r = snow::Builder::new(params.clone());
    let keypair_r = builder_r.generate_keypair()?;
    let mut h_r = builder_r.local_private_key(&keypair_r.private)?.build_responder()?;

    let builder_i = snow::Builder::new(params);
    let key_i = builder_i.generate_keypair()?.private;
    let mut h_i = builder_i
        .local_private_key(&key_i)?
        .remote_public_key(&keypair_r.public)?
        .build_initiator()?;

    let mut buffer_msg = vec![0_u8; 65535].into_boxed_slice();
    let mut buffer_out = vec![0_u8; 65535].into_boxed_slice();
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_ok());

    let len = h_r.write_message(b"abc", &mut buffer_msg)?;
    let res = h_i.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_ok());

    let _len = h_i.write_message(b"abc", &mut buffer_msg)?;
    let res = h_r.read_message(&buffer_msg[..2], &mut buffer_out);

    assert!(res.is_err());
    Ok(())
}

#[test]
fn test_buffer_issues_encrypted_handshake() -> TestResult {
    let params: NoiseParams = "Noise_IKpsk2_25519_ChaChaPoly_SHA256".parse()?;

    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);

    let static_i = b_i.generate_keypair()?;
    let static_r = b_r.generate_keypair()?;

    let mut h_i = b_i
        .psk(2, &[32_u8; 32])?
        .local_private_key(&static_i.private)?
        .remote_public_key(&static_r.public)?
        .build_initiator()?;
    let mut h_r = b_r
        .psk(2, &[32_u8; 32])?
        .local_private_key(&static_r.private)?
        .remote_public_key(&static_i.public)?
        .build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 2];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_err());
    Ok(())
}

#[test]
fn test_send_trait() {
    use std::{sync::mpsc::channel, thread};

    let (tx, rx) = channel();
    thread::spawn(move || {
        let session = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .build_initiator()
            .unwrap();
        tx.send(session).unwrap();
    });
    let _session = rx.recv().expect("failed to receive noise session");
}

#[test]
fn test_checkpointing() -> TestResult {
    let params: NoiseParams = "Noise_XXpsk2_25519_ChaChaPoly_SHA256".parse()?;

    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);

    let static_i = b_i.generate_keypair()?;
    let static_r = b_r.generate_keypair()?;

    let mut h_i = b_i
        .psk(2, &[32_u8; 32])?
        .local_private_key(&static_i.private)?
        .remote_public_key(&static_r.public)?
        .build_initiator()?;
    let mut h_r = b_r
        .psk(2, &[32_u8; 32])?
        .local_private_key(&static_r.private)?
        .remote_public_key(&static_i.public)?
        .build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_bad = [0_u8; 48];

    let res = h_i.write_message(b"abc", &mut buffer_bad);
    assert!(res.is_err(), "write_message() should have failed for insufficiently-sized buffer");

    let len = h_i
        .write_message(b"abc", &mut buffer_msg)
        .expect("write_message() should have succeeded for correctly-sized buffer");

    let mut buffer_bad = [0_u8; 2];
    let mut buffer_ok = [0_u8; 200];
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_bad);
    assert!(res.is_err(), "read_message() should have failed for insufficiently-sized buffer");

    let _res = h_r
        .read_message(&buffer_msg[..len], &mut buffer_ok)
        .expect("read_message() should have succeeded");
    Ok(())
}

#[test]
fn test_get_remote_static() -> TestResult {
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i =
        Builder::new(params.clone()).local_private_key(&get_inc_key(0))?.build_initiator()?;
    let mut h_r = Builder::new(params).local_private_key(&get_inc_key(1))?.build_responder()?;

    let mut buf = [0_u8; 1024];
    let mut buf2 = [0_u8; 1024];

    // XX(s, rs):
    assert!(h_i.get_remote_static().is_none());
    assert!(h_r.get_remote_static().is_none());

    // -> e
    let len = h_i.write_message(&[], &mut buf)?;
    let _ = h_r.read_message(&buf[..len], &mut buf2)?;

    assert!(h_i.get_remote_static().is_none());
    assert!(h_r.get_remote_static().is_none());

    // <- e, ee s, es
    let len = h_r.write_message(&[], &mut buf)?;
    let _ = h_i.read_message(&buf[..len], &mut buf2)?;

    assert_eq!(
        h_i.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES)
    );
    assert!(h_r.get_remote_static().is_none());

    // -> s, se
    let len = h_i.write_message(&[], &mut buf)?;
    let _ = h_r.read_message(&buf[..len], &mut buf2)?;

    assert_eq!(
        h_i.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES)
    );
    assert_eq!(
        h_r.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES)
    );
    Ok(())
}

#[test]
fn test_set_psk() -> TestResult {
    let params: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i =
        Builder::new(params.clone()).local_private_key(&get_inc_key(0))?.build_initiator()?;
    let mut h_r = Builder::new(params).local_private_key(&get_inc_key(1))?.build_responder()?;

    let mut buf = [0_u8; 1024];
    let mut buf2 = [0_u8; 1024];

    let psk = get_inc_key(3);

    // XX(s, rs):
    // -> e
    let len = h_i.write_message(&[], &mut buf)?;
    let _ = h_r.read_message(&buf[..len], &mut buf2)?;

    // <- e, ee s, es
    let len = h_r.write_message(&[], &mut buf)?;
    let _ = h_i.read_message(&buf[..len], &mut buf2)?;

    h_i.set_psk(3, &psk)?;
    h_r.set_psk(3, &psk)?;

    // -> s, se, psk
    let len = h_i.write_message(&[], &mut buf)?;
    let _ = h_r.read_message(&buf[..len], &mut buf2)?;
    Ok(())
}

#[test]
fn test_stateless_sanity_session() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let h_i = h_i.into_stateless_transport_mode()?;
    let h_r = h_r.into_stateless_transport_mode()?;

    let len = h_i.write_message(1337, b"hack the planet", &mut buffer_msg)?;
    let len = h_r.read_message(1337, &buffer_msg[..len], &mut buffer_out)?;
    assert_eq!(&buffer_out[..len], b"hack the planet");
    Ok(())
}

#[test]
fn test_handshake_read_oob_error() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    // This shouldn't panic, but it *should* return an error.
    let _ = h_i.read_message(&buffer_msg[..len], &mut buffer_out);
    Ok(())
}

#[test]
fn test_stateful_nonce_maxiumum_behavior() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let h_i = h_i.into_stateless_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let mut sender_nonce = u64::MAX - 2;
    let len = h_i.write_message(sender_nonce, b"xyz", &mut buffer_msg)?;

    h_r.set_receiving_nonce(sender_nonce);
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    // Simulate exhausting the nonce space for the stateful transport.
    sender_nonce += 1;
    let len = h_i.write_message(sender_nonce, b"abc", &mut buffer_msg)?;

    h_r.set_receiving_nonce(sender_nonce + 1); // u64::MAX

    // This should fail because we've simulated exhausting the nonce space, as the spec says 2^64-1 is reserved
    // and may not be used in the `CipherState` object.
    assert!(matches!(
        dbg!(h_r.read_message(&buffer_msg[..len], &mut buffer_out)),
        Err(snow::Error::State(snow::error::StateProblem::Exhausted))
    ));
    Ok(())
}

#[test]
fn test_stateless_nonce_maximum_behavior() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let h_i = h_i.into_stateless_transport_mode()?;
    let h_r = h_r.into_stateless_transport_mode()?;

    let max_nonce = u64::MAX;

    assert!(matches!(
        h_i.write_message(max_nonce, b"xyz", &mut buffer_msg),
        Err(snow::Error::State(snow::error::StateProblem::Exhausted))
    ));

    assert!(matches!(
        h_r.read_message(max_nonce, &buffer_msg, &mut buffer_out),
        Err(snow::Error::State(snow::error::StateProblem::Exhausted))
    ));
    Ok(())
}

#[test]
fn test_stateful_nonce_increment_behavior() -> TestResult {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse()?;
    let mut h_i = Builder::new(params.clone()).build_initiator()?;
    let mut h_r = Builder::new(params).build_responder()?;

    let mut buffer_msg = [0_u8; 200];
    let mut buffer_out = [0_u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg)?;
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let len = h_r.write_message(b"defg", &mut buffer_msg)?;
    h_i.read_message(&buffer_msg[..len], &mut buffer_out)?;

    let mut h_i = h_i.into_transport_mode()?;
    let mut h_r = h_r.into_transport_mode()?;

    let len = h_i.write_message(b"xyz", &mut buffer_msg)?;

    // Corrupt the message by incrementing a byte in the payload
    let mut corrupted = buffer_msg[..len].to_owned();
    corrupted[0] = corrupted[0].wrapping_add(1);

    // This should result in an error, but should not change any internal state
    assert!(h_r.read_message(&corrupted, &mut buffer_out).is_err());

    // This should now succeed as the nonce counter should have remained the same
    h_r.read_message(&buffer_msg[..len], &mut buffer_out)?;

    // This should now fail again as the nonce counter should have incremented
    assert!(h_r.read_message(&buffer_msg[..len], &mut buffer_out).is_err());
    Ok(())
}
