extern crate snow;
extern crate rustc_serialize;

use std::ops::Deref;
use rustc_serialize::{Decodable, Decoder};
use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::json;
use snow::*;
use snow::params::*;
use std::fmt;

struct HexBytes {
    original: String,
    payload: Vec<u8>,
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

impl Decodable for HexBytes {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let hex = d.read_str()?;
        let bytes = hex.from_hex().map_err(|_| d.error("field is an invalid binary hex encoding"))?;
        Ok(HexBytes {
            original: hex,
            payload: bytes,
        })
    }
}

#[derive(RustcDecodable)]
struct TestMessage {
    payload: HexBytes,
    ciphertext: HexBytes,
}

impl fmt::Debug for TestMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Message")
    }
}

#[derive(RustcDecodable, Debug)]
struct TestVector {
    name: String,
    pattern: String,
    dh: String,
    cipher: String,
    hash: String,
    init_prologue: HexBytes,
    init_psk: Option<HexBytes>,
    init_static: Option<HexBytes>,
    init_remote_static: Option<HexBytes>,
    init_ephemeral: Option<HexBytes>,
    resp_prologue: HexBytes,
    resp_static: Option<HexBytes>,
    resp_remote_static: Option<HexBytes>,
    resp_ephemeral: Option<HexBytes>,
    resp_psk: Option<HexBytes>,
    messages: Vec<TestMessage>,
}

#[derive(RustcDecodable)]
struct TestVectors {
    vectors: Vec<TestVector>,
}

fn build_session_pair(vector: &TestVector) -> Result<(Session, Session), NoiseError> {
    let params: NoiseParams = vector.name.parse().unwrap();
    let mut init_builder = NoiseBuilder::new(params.clone());
    let mut resp_builder = NoiseBuilder::new(params);

    match (params.base, &vector.init_psk, &vector.resp_psk) {
        (BaseChoice::NoisePSK, &Some(ref init_psk), &Some(ref resp_psk)) => {
            init_builder = init_builder.preshared_key(&*init_psk);
            resp_builder = resp_builder.preshared_key(&*resp_psk);
        },
        (BaseChoice::NoisePSK, _, _) => {
            panic!("NoisePSK case missing PSKs for init and/or resp");
        },
        _ => {}
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
            s.push_str(&format!("plaintext: {}\n", &(*message.payload)[..].to_hex()));
            s.push_str(&format!("expected:  {}\n", &(*message.ciphertext)[..].to_hex()));
            s.push_str(&format!("actual:    {}", &sendbuf[..len].to_hex()));
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
            s.push_str(&format!("plaintext: {}\n", &(*message.payload)[..].to_hex()));
            s.push_str(&format!("expected:  {}\n", &(*message.ciphertext)[..].to_hex()));
            s.push_str(&format!("actual:    {}", &sendbuf[..message.ciphertext.len()].to_hex()));
            return Err(s)
        }
    }
    Ok(())
}

fn test_vectors_from_json(json: &str) {
    let test_vectors: TestVectors = json::decode(json).unwrap();

    let mut passes = 0;
    let mut fails = 0;
    let mut ignored_448 = 0;

    for vector in test_vectors.vectors {
        let params: NoiseParams = vector.name.parse().unwrap();
        if params.dh == DHChoice::Ed448 {
            ignored_448 += 1;
            continue;
        }
        let (init, resp) = build_session_pair(&vector).unwrap();

        match confirm_message_vectors(init, resp, &vector.messages, params.handshake.is_oneway()) {
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
    println!("* ignored {} Ed448-Goldilocks variants", ignored_448);
    if fails > 0 {
        panic!("at least one vector failed.");
    }
}

#[test]
fn test_vectors_noise_c_basic() {
    test_vectors_from_json(include_str!("vectors/noise-c-basic.txt"));
}

#[test]
fn test_vectors_cacophony() {
    test_vectors_from_json(include_str!("vectors/cacophony.txt"));
}
