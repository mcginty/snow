#![allow(non_snake_case)]
extern crate snow;
extern crate rustc_serialize;

mod vectors;

use snow::*;
use std::ops::DerefMut;
use vectors::*;
use self::rustc_serialize::hex::ToHex;

struct RandomInc {
    next_byte: u8
}

impl Default for RandomInc {

    fn default() -> RandomInc {
        RandomInc {next_byte: 0}
    }
}

impl RandomType for RandomInc {

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

struct TestResolver {
    next_byte: u8,
    parent: DefaultResolver,
}

impl TestResolver {
    pub fn new(next_byte: u8) -> Self {
        TestResolver{ next_byte: next_byte, parent: DefaultResolver }
    }

    pub fn next_byte(&mut self, next_byte: u8) {
        self.next_byte = next_byte;
    }
}

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<RandomType>> {
        let mut rng = RandomInc::default();
        rng.next_byte = self.next_byte;
        Some(Box::new(rng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<DhType>> {
        self.parent.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<HashType>> {
        self.parent.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<CipherStateType>> {
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
fn test_noise_X_with_builder() {
    let mut resolver = TestResolver::new(0);
    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    let mut rng = resolver.resolve_rng().unwrap();

    static_i.generate(rng.deref_mut());
    static_r.generate(rng.deref_mut());

    println!("i: {}", static_i.privkey().to_hex());
    println!("r: {}", static_r.pubkey().to_hex());

    resolver.next_byte(64);

    let mut h = NoiseBuilder::with_resolver("Noise_X_25519_ChaChaPoly_SHA256".parse().unwrap(),
                                                  Box::new(resolver))
        .local_private_key(static_i.privkey())
        .remote_public_key(static_r.pubkey())
        .build_initiator().unwrap();

    let mut buffer = [0u8; 96];
    assert!(h.write_message(&[0u8;0], &mut buffer).unwrap() == 96);
    println!("{}", buffer.to_hex());
    assert!(buffer.to_hex() == "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d7f2cf1b1c5af10e38a09a9bb7e3b1d589a99492cc50293eaa1f3f391b59bb6990d");
}

#[test]
fn test_noise_NN_with_builder() {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);
    let mut h_i = NoiseBuilder::with_resolver("Noise_NN_25519_AESGCM_SHA512".parse().unwrap(),
                                                  Box::new(resolver_i))
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_NN_25519_AESGCM_SHA512".parse().unwrap(),
                                                  Box::new(resolver_r))
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; 64];
    let mut buffer_out = [0u8; 10];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap() == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap() == 3);
    assert!(buffer_out[..3].to_hex() == "616263");
    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap() == 52);
    assert!(h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap() == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");
    assert!(buffer_msg[..52].to_hex() == "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0");
}

#[test]
fn test_noise_XX_with_builder() {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());
    println!("key_i: {:?}", static_i.privkey());
    println!("key_r: {:?}", static_r.privkey());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                                  Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                                  Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap() == 35);
    println!("msg1: {:?}", &buffer_msg[..35]);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap() == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap() == 100);
    println!("msg2: {:?}", &buffer_msg[..100]);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap() == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap() == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap() == 0);

    assert!(buffer_msg[..64].to_hex() == "8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7");

}

#[test]
fn test_noise_IK_with_builder() {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());
    println!("key_i: {:?}", static_i.privkey());
    println!("key_r: {:?}", static_r.privkey());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_IK_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .remote_public_key(static_r.pubkey())
        .build_initiator().unwrap();

    let mut h_r = NoiseBuilder::with_resolver("Noise_IK_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    println!("a");
    h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    println!("a");
    h_r.read_message(&buffer_msg[..99], &mut buffer_out).unwrap();
    assert!(buffer_out[..3].to_hex() == "616263");

    println!("a");
    h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    println!("a");
    h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap();
    println!("a");
    assert!(buffer_out[..4].to_hex() == "64656667");

    //println!("{}", buffer_msg[..52].to_hex());
}

//#[test]
//fn test_noise_IK_with_builder() {
//    let resolver_i = TestResolver::new(0);
//    let resolver_r = TestResolver::new(1);
//
//    let mut static_i:Dh25519 = Default::default();
//    let mut static_r:Dh25519 = Default::default();
//
//    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
//    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());
//    println!("key_i: {:?}", static_i.privkey());
//    println!("key_r: {:?}", static_r.privkey());
//
//    let resolver_i = TestResolver::new(32);
//    let resolver_r = TestResolver::new(33);
//
//    let mut h_i = NoiseBuilder::with_resolver("Noise_IK_25519_AESGCM_SHA256".parse().unwrap(),
//                                                  Box::new(resolver_i))
//        .local_private_key(static_i.privkey())
//        .remote_public_key(static_r.pubkey())
//        .prologue("ABC".as_bytes())
//        .build_initiator().unwrap();
//
//    let mut h_r = NoiseBuilder::with_resolver("Noise_IK_25519_AESGCM_SHA256".parse().unwrap(),
//                                                  Box::new(resolver_r))
//        .local_private_key(static_r.privkey())
//        .prologue("ABC".as_bytes())
//        .build_responder().unwrap();
//
//    let mut buffer_msg = [0u8; 200];
//    let mut buffer_out = [0u8; 200];
//    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 99);
//    assert!(h_r.read_message(&buffer_msg[..99], &mut buffer_out).unwrap().0 == 3);
//    assert!(buffer_out[..3].to_hex() == "616263");
//
//    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 52);
//    assert!(h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap().0 == 4);
//    assert!(buffer_out[..4].to_hex() == "64656667");
//
//    //println!("{}", buffer_msg[..52].to_hex());
//    assert!(buffer_msg[..52].to_hex() == "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b7555a94199d0ce2972e0861b06c2152419a278de");
//}

#[test]
fn test_noise_session_transition_change() {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i = Dh25519::default();
    let mut static_r = Dh25519::default();

    static_i.generate(&mut *resolver_i.resolve_rng().unwrap());
    static_r.generate(&mut *resolver_r.resolve_rng().unwrap());
    println!("key_i: {:?}", static_i.privkey());
    println!("key_r: {:?}", static_r.privkey());

    let params: NoiseParams = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = NoiseBuilder::new(params)
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(params)
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap() == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap() == 3);

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap() == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap() == 4);

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap() == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap() == 0);

    assert!(h_i.is_handshake_finished());
    let final_ciphers = h_i.transition().unwrap();
}

