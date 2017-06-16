#![cfg(feature = "vector-tests")]
extern crate hex;
extern crate snow;

#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate rand;

use serde::de::{self, Deserialize, Deserializer, Visitor, Unexpected};
use serde::ser::{Serialize, Serializer};
use std::ops::Deref;
use hex::{FromHex, ToHex};
use snow::{NoiseBuilder, Session};
use snow::params::*;
use snow::types::Dh;
use snow::wrappers::crypto_wrapper::Dh25519;
use snow::wrappers::rand_wrapper::RandomOs;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;

#[derive(Clone)]
struct HexBytes {
    original: String,
    payload: Vec<u8>,
}

impl From<Vec<u8>> for HexBytes {
    fn from(payload: Vec<u8>) -> Self {
        Self {
            original: payload.to_hex(),
            payload: payload,
        }
    }
}

impl Deref for HexBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.original)
    }
}

struct HexBytesVisitor;
impl<'de> Visitor<'de> for HexBytesVisitor {
    type Value = HexBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        let bytes = Vec::<u8>::from_hex(s).map_err(|_| de::Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(HexBytes {
            original: s.to_owned(),
            payload: bytes,
        })
    }

}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<HexBytes, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_str(HexBytesVisitor)
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_hex())
    }
}

#[derive(Serialize, Deserialize)]
struct TestMessage {
    payload: HexBytes,
    ciphertext: HexBytes,
}

impl fmt::Debug for TestMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Message")
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TestVector {
    #[serde(skip_serializing_if="Option::is_none")] name: Option<String>,
    protocol_name: String,
    #[serde(skip_serializing_if="Option::is_none")] hybrid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")] fail: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")] fallback: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")] fallback_pattern: Option<String>,
    init_prologue: HexBytes,
    #[serde(skip_serializing_if="Option::is_none")] init_psks: Option<Vec<HexBytes>>,
    #[serde(skip_serializing_if="Option::is_none")] init_static: Option<HexBytes>,
    #[serde(skip_serializing_if="Option::is_none")] init_ephemeral: Option<HexBytes>,
    #[serde(skip_serializing_if="Option::is_none")] init_remote_static: Option<HexBytes>,
    resp_prologue: HexBytes,
    #[serde(skip_serializing_if="Option::is_none")] resp_psks: Option<Vec<HexBytes>>,
    #[serde(skip_serializing_if="Option::is_none")] resp_static: Option<HexBytes>,
    #[serde(skip_serializing_if="Option::is_none")] resp_ephemeral: Option<HexBytes>,
    #[serde(skip_serializing_if="Option::is_none")] resp_remote_static: Option<HexBytes>,
    messages: Vec<TestMessage>,
}

#[derive(Serialize, Deserialize)]
struct TestVectors {
    vectors: Vec<TestVector>,
}

fn build_session_pair(vector: &TestVector) -> Result<(Session, Session), snow::Error> {
    let params: NoiseParams = vector.protocol_name.parse().unwrap();
    let mut init_builder = NoiseBuilder::new(params.clone());
    let mut resp_builder = NoiseBuilder::new(params.clone());

    if params.handshake.is_psk() {
        let mut psk_index = 0;
        if let (&Some(ref ipsks), &Some(ref rpsks)) = (&vector.init_psks, &vector.resp_psks) {
            for modifier in params.handshake.modifiers.list {
                if let HandshakeModifier::Psk(n) = modifier {
                    init_builder = init_builder.psk(n, &*ipsks[psk_index]);
                    resp_builder = resp_builder.psk(n, &*rpsks[psk_index]);
                    psk_index += 1;
                }
            }
        } else {
            panic!("missing PSKs for a PSK-mode handshake");
        }
    }

    if let Some(ref init_s) = vector.init_static {
        init_builder = init_builder.local_private_key(&*init_s);
    }
    if let Some(ref resp_s) = vector.resp_static {
        resp_builder = resp_builder.local_private_key(&*resp_s);
    }
    if let Some(ref init_remote_static) = vector.init_remote_static {
        init_builder = init_builder.remote_public_key(&*init_remote_static);
    }
    if let Some(ref resp_remote_static) = vector.resp_remote_static {
        resp_builder = resp_builder.remote_public_key(&*resp_remote_static);
    }
    if let Some(ref init_e) = vector.init_ephemeral {
        init_builder = init_builder.fixed_ephemeral_key_for_testing_only(&*init_e);
    }
    if let Some(ref resp_e) = vector.resp_ephemeral {
        resp_builder = resp_builder.fixed_ephemeral_key_for_testing_only(&*resp_e);
    }

    let init = init_builder.prologue(&vector.init_prologue).build_initiator()?;
    let resp = resp_builder.prologue(&vector.resp_prologue).build_responder()?;

    Ok((init, resp))
}

fn confirm_message_vectors(mut init: Session, mut resp: Session, messages_vec: &Vec<TestMessage>, is_oneway: bool) -> Result<(), String> {
    let (mut sendbuf, mut recvbuf) = ([0u8; 65535], [0u8; 65535]);
    let mut messages = messages_vec.iter().enumerate();
    while !init.is_handshake_finished() {
        let (i, message) = messages.next().unwrap();
        let (send, recv) = if i % 2 == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };

        let len = send.write_message(&*message.payload, &mut sendbuf).map_err(|_| format!("write_message failed on message {}", i))?;
        recv.read_message(&sendbuf[..len], &mut recvbuf).map_err(|_| format!("read_message failed on message {}", i))?;
        if &sendbuf[..len] != &(*message.ciphertext)[..] {
            let mut s = String::new();
            s.push_str(&format!("message {}", i));
            s.push_str(&format!("plaintext: {}\n", message.payload.to_hex()));
            s.push_str(&format!("expected:  {}\n", message.ciphertext.to_hex()));
            s.push_str(&format!("actual:    {}", &sendbuf[..len].to_owned().to_hex()));
            return Err(s)
        }
    }

    let (mut init, mut resp) = (init.into_transport_mode().unwrap(), resp.into_transport_mode().unwrap());
    for (i, message) in messages {
        let (send, recv) = if is_oneway || i % 2 == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };

        let len = send.write_message(&*message.payload, &mut sendbuf).unwrap();
        recv.read_message(&sendbuf[..len], &mut recvbuf).unwrap();
        if &sendbuf[..len] != &(*message.ciphertext)[..] {
            let mut s = String::new();
            s.push_str(&format!("message {}", i));
            s.push_str(&format!("plaintext: {}\n", message.payload.to_hex()));
            s.push_str(&format!("expected:  {}\n", message.ciphertext.to_hex()));
            s.push_str(&format!("actual:    {}", &sendbuf[..message.ciphertext.len()].to_owned().to_hex()));
            return Err(s)
        }
    }
    Ok(())
}

fn test_vectors_from_json(json: &str) {
    let test_vectors: TestVectors = serde_json::from_str(json).unwrap();

    let mut passes = 0;
    let mut fails = 0;
    let mut ignored = 0;

    for vector in test_vectors.vectors {
        let params: NoiseParams = vector.protocol_name.parse().unwrap();
        if params.dh == DHChoice::Ed448 {
            ignored += 1;
            continue;
        }
        let (init, resp) = build_session_pair(&vector).unwrap();

        match confirm_message_vectors(init, resp, &vector.messages, params.handshake.pattern.is_oneway()) {
            Ok(_) => {
                passes += 1;
            },
            Err(s) => {
                fails += 1;
                println!("FAIL");
                println!("{}", s);
                println!("{:?}", vector);
            }
        }
    }

    println!("\n{}/{} passed", passes, passes+fails);
    println!("* ignored {} unsupported variants", ignored);
    if fails > 0 {
        panic!("at least one vector failed.");
    }
}

// ignore until noise-c updates the test vectors to new format.
//#[test]
//fn test_vectors_noise_c_basic() {
//    test_vectors_from_json(include_str!("vectors/noise-c-basic.txt"));
//}

fn random_vec(size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size);
    for _ in 0..size {
        v.push(rand::random());
    }
    v
}

fn get_psks_count(params: &NoiseParams) -> usize {
    let mut count = 0;
    for modifier in &params.handshake.modifiers.list {
        if let &HandshakeModifier::Psk(_) = modifier {
            count += 1;
        }
    }
    count
}

fn generate_multipsk_vector(params: NoiseParams) -> TestVector {
    let prologue = "There is no right and wrong. There's only fun and boring.".as_bytes().to_vec();
    let mut rand = RandomOs::default();
    let mut is = Dh25519::default();
    let mut ie = Dh25519::default();
    let mut rs = Dh25519::default();
    let mut re = Dh25519::default();
    is.generate(&mut rand);
    ie.generate(&mut rand);
    rs.generate(&mut rand);
    re.generate(&mut rand);
    let mut psks = vec![];
    let mut psks_hex = vec![];

    let mut init_b: NoiseBuilder = NoiseBuilder::new(params.clone());
    let mut resp_b: NoiseBuilder = NoiseBuilder::new(params.clone());

    for _ in 0..get_psks_count(&params) {
        let v = random_vec(32);
        psks_hex.push(v.clone().into());
        psks.push(v);
    }

    let mut psk_index = 0;
    for modifier in params.handshake.modifiers.list {
        if let HandshakeModifier::Psk(n) = modifier {
            init_b = init_b.psk(n, &psks[psk_index]);
            resp_b = resp_b.psk(n, &psks[psk_index]);
            psk_index += 1;
        }
    }
    init_b = init_b.local_private_key(&is.privkey());
    init_b = init_b.fixed_ephemeral_key_for_testing_only(&ie.privkey());
    init_b = init_b.prologue(&prologue);
    resp_b = resp_b.local_private_key(&rs.privkey());
    resp_b = resp_b.fixed_ephemeral_key_for_testing_only(&re.privkey());
    resp_b = resp_b.prologue(&prologue);

    let mut init: Session = init_b.build_initiator().unwrap();
    let mut resp: Session = resp_b.build_responder().unwrap();

    let (mut ibuf, mut obuf) = ([0u8; 65535], [0u8; 65535]);
    let mut messages = vec![];
    while !(init.is_handshake_finished() && resp.is_handshake_finished()) {
        let payload = random_vec(32);
        let len = init.write_message(&payload, &mut ibuf).unwrap();
        messages.push(TestMessage {
            payload: payload.clone().into(),
            ciphertext: ibuf[..len].to_vec().into(),
        });
        let _ = resp.read_message(&ibuf[..len], &mut obuf).unwrap();

        if init.is_handshake_finished() && resp.is_handshake_finished() {
            break;
        }

        let payload = random_vec(32);
        let len = resp.write_message(&payload, &mut ibuf).unwrap();
        messages.push(TestMessage {
            payload: payload.clone().into(),
            ciphertext: ibuf[..len].to_vec().into(),
        });
        let _ = init.read_message(&ibuf[..len], &mut obuf).unwrap();
    }

    TestVector {
        name: None,
        protocol_name: params.name,
        hybrid: None,
        fail: None,
        fallback: None,
        fallback_pattern: None,
        init_prologue: prologue.clone().into(),
        init_psks: Some(psks_hex.clone()),
        init_static: Some(is.privkey().to_vec().into()),
        init_ephemeral: Some(ie.privkey().to_vec().into()),
        init_remote_static: None,
        resp_prologue: prologue.clone().into(),
        resp_psks: Some(psks_hex.clone()),
        resp_static: Some(rs.privkey().to_vec().into()),
        resp_ephemeral: Some(re.privkey().to_vec().into()),
        resp_remote_static: None,
        messages: messages,
    }
}

fn generate_multipsk_vector_set() -> TestVectors {
    let handshakes = vec!["XXpsk0+psk1", "XXpsk0+psk2", "XXpsk0+psk3", "XXpsk0+psk1+psk2+psk3"];
    let ciphers = vec!["ChaChaPoly", "AESGCM"];
    let hashes = vec!["BLAKE2s", "BLAKE2b", "SHA256", "SHA512"];

    let mut vectors = vec![];

    for handshake in &handshakes {
        for cipher in &ciphers {
            for hash in &hashes {
                let protocol_name = format!("Noise_{}_25519_{}_{}", handshake, cipher, hash);
                vectors.push(generate_multipsk_vector(protocol_name.parse().unwrap()));
            }
        }
    }
    TestVectors { vectors }
}

#[test]
fn test_vectors_cacophony() {
    test_vectors_from_json(include_str!("vectors/cacophony.txt"));
}

#[test]
fn test_vectors_snow_multipsk() {
    let file = OpenOptions::new().write(true).create_new(true).open("tests/vectors/snow-multipsk.txt");
    if let Ok(mut file) = file {
        serde_json::to_writer_pretty(&mut file, &generate_multipsk_vector_set()).unwrap();
    }
    let mut file = File::open("tests/vectors/snow-multipsk.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    test_vectors_from_json(&contents);
}
