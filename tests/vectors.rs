#![cfg(feature = "vector-tests")]
#![allow(clippy::std_instead_of_core)]
#[macro_use]
extern crate serde_derive;

use hex::FromHex;
use rand::RngCore;
use serde::{
    de::{self, Deserialize, Deserializer, Unexpected, Visitor},
    ser::{Serialize, Serializer},
};
use snow::{params::*, Builder, HandshakeState};
use std::{
    fmt,
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::Read,
    marker::PhantomData,
    ops::Deref,
};

#[derive(Clone)]
struct HexBytes<T> {
    original: String,
    payload:  T,
}

impl<T: AsRef<[u8]>> From<T> for HexBytes<T> {
    fn from(payload: T) -> Self {
        Self { original: hex::encode(&payload), payload }
    }
}

impl<T> Deref for HexBytes<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> fmt::Debug for HexBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.original)
    }
}

struct HexBytesVisitor<T: AsRef<[u8]>>(PhantomData<T>);
impl<T: AsRef<[u8]> + FromHex> Visitor<'_> for HexBytesVisitor<T> {
    type Value = HexBytes<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes =
            T::from_hex(s).map_err(|_| de::Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(HexBytes { original: s.to_owned(), payload: bytes })
    }
}

impl<'de, T: AsRef<[u8]> + FromHex> Deserialize<'de> for HexBytes<T> {
    fn deserialize<D>(deserializer: D) -> Result<HexBytes<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HexBytesVisitor(PhantomData))
    }
}

impl<T: AsRef<[u8]>> Serialize for HexBytes<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.payload))
    }
}

#[derive(Serialize, Deserialize)]
struct TestMessage {
    payload:    HexBytes<Vec<u8>>,
    ciphertext: HexBytes<Vec<u8>>,
}

impl fmt::Debug for TestMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Message")
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TestVector {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    protocol_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    hybrid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fail: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_pattern: Option<String>,

    init_prologue: HexBytes<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    init_psks: Option<Vec<HexBytes<[u8; 32]>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    init_static: Option<HexBytes<Vec<u8>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    init_ephemeral: Option<HexBytes<Vec<u8>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    init_remote_static: Option<HexBytes<Vec<u8>>>,

    resp_prologue:      HexBytes<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_psks:          Option<Vec<HexBytes<[u8; 32]>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_static:        Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_ephemeral:     Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_remote_static: Option<HexBytes<Vec<u8>>>,

    messages: Vec<TestMessage>,
}

#[derive(Serialize, Deserialize)]
struct TestVectors {
    vectors: Vec<TestVector>,
}

fn build_session_pair(vector: &TestVector) -> Result<(HandshakeState, HandshakeState), String> {
    let params: NoiseParams = vector.protocol_name.parse().unwrap();
    let mut init_builder = Builder::new(params.clone());
    let mut resp_builder = Builder::new(params.clone());

    if params.handshake.is_psk() {
        let mut psk_index = 0;
        if let (Some(ipsks), Some(rpsks)) = (&vector.init_psks, &vector.resp_psks) {
            for modifier in params.handshake.modifiers.list {
                if let HandshakeModifier::Psk(n) = modifier {
                    init_builder = init_builder.psk(n, &ipsks[psk_index]).unwrap();
                    resp_builder = resp_builder.psk(n, &rpsks[psk_index]).unwrap();
                    psk_index += 1;
                }
            }
        } else {
            return Err("missing PSKs for a PSK-mode handshake".into());
        }
    }

    if let Some(ref init_s) = vector.init_static {
        init_builder = init_builder.local_private_key(init_s).unwrap();
    }
    if let Some(ref resp_s) = vector.resp_static {
        resp_builder = resp_builder.local_private_key(resp_s).unwrap();
    }
    if let Some(ref init_remote_static) = vector.init_remote_static {
        init_builder = init_builder.remote_public_key(init_remote_static).unwrap();
    }
    if let Some(ref resp_remote_static) = vector.resp_remote_static {
        resp_builder = resp_builder.remote_public_key(resp_remote_static).unwrap();
    }
    if let Some(ref init_e) = vector.init_ephemeral {
        init_builder = init_builder.fixed_ephemeral_key_for_testing_only(init_e);
    }
    if let Some(ref resp_e) = vector.resp_ephemeral {
        resp_builder = resp_builder.fixed_ephemeral_key_for_testing_only(resp_e);
    }

    let init = init_builder
        .prologue(&vector.init_prologue)
        .unwrap()
        .build_initiator()
        .map_err(|e| format!("{e:?}"))?;
    let resp = resp_builder
        .prologue(&vector.resp_prologue)
        .unwrap()
        .build_responder()
        .map_err(|e| format!("{e:?}"))?;

    Ok((init, resp))
}

fn confirm_message_vectors(
    mut init_hs: HandshakeState,
    mut resp_hs: HandshakeState,
    messages: &[TestMessage],
    is_oneway: bool,
) -> Result<(), String> {
    let (mut sendbuf, mut recvbuf) =
        (vec![0_u8; 65535].into_boxed_slice(), vec![0_u8; 65535].into_boxed_slice());
    let mut messages_iter = messages.iter().enumerate();
    while !init_hs.is_handshake_finished() {
        let (i, message) = messages_iter.next().unwrap();
        let (send, recv) =
            if i % 2 == 0 { (&mut init_hs, &mut resp_hs) } else { (&mut resp_hs, &mut init_hs) };

        let len = send
            .write_message(&message.payload, &mut sendbuf)
            .map_err(|_| format!("write_message failed on message {i}"))?;
        let recv_len = recv
            .read_message(&sendbuf[..len], &mut recvbuf)
            .map_err(|_| format!("read_message failed on message {i}"))?;
        if sendbuf[..len] != (*message.ciphertext)[..] || *message.payload != recvbuf[..recv_len] {
            let mut s = String::new();
            writeln!(&mut s, "message {i}").unwrap();
            writeln!(&mut s, "plaintext: {}", hex::encode(&*message.payload)).unwrap();
            writeln!(&mut s, "expected:  {}", hex::encode(&*message.ciphertext)).unwrap();
            writeln!(&mut s, "actual:    {}", hex::encode(&sendbuf[..len])).unwrap();
            return Err(s);
        }
    }

    let (mut init, mut resp) =
        (init_hs.into_transport_mode().unwrap(), resp_hs.into_transport_mode().unwrap());
    for (i, message) in messages_iter {
        let (send, recv) =
            if is_oneway || i % 2 == 0 { (&mut init, &mut resp) } else { (&mut resp, &mut init) };

        let len = send.write_message(&message.payload, &mut sendbuf).unwrap();
        let recv_len = recv.read_message(&sendbuf[..len], &mut recvbuf).unwrap();
        if sendbuf[..len] != (*message.ciphertext)[..] || *message.payload != recvbuf[..recv_len] {
            let mut s = String::new();
            writeln!(&mut s, "message {i}").unwrap();
            writeln!(&mut s, "plaintext          : {}", hex::encode(&*message.payload)).unwrap();
            writeln!(&mut s, "expected ciphertext: {}", hex::encode(&*message.ciphertext)).unwrap();
            writeln!(
                &mut s,
                "actual ciphertext  : {}",
                hex::encode(&sendbuf[..message.ciphertext.len()])
            )
            .unwrap();
            writeln!(&mut s, "actual plaintext   : {}", hex::encode(&recvbuf[..recv_len])).unwrap();
            return Err(s);
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
        let Ok(params) = vector.protocol_name.parse::<NoiseParams>() else {
            ignored += 1;
            continue;
        };
        if params.dh == DHChoice::Curve448 {
            ignored += 1;
            continue;
        }

        let (init, resp) = match build_session_pair(&vector) {
            Ok((init, resp)) => (init, resp),
            Err(s) => {
                fails += 1;
                println!("FAIL");
                println!("{s}");
                println!("{vector:?}");
                continue;
            },
        };

        match confirm_message_vectors(
            init,
            resp,
            &vector.messages,
            params.handshake.pattern.is_oneway(),
        ) {
            Ok(()) => {
                passes += 1;
            },
            Err(s) => {
                fails += 1;
                println!("FAIL");
                println!("{s}");
                println!("{vector:?}");
            },
        }
    }

    println!("\n{}/{} passed", passes, passes + fails);
    println!("* ignored {ignored} unsupported variants");
    assert!(fails <= 0, "at least one vector failed.");
}

fn random_slice<const N: usize>() -> [u8; N] {
    let mut v = [0_u8; N];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut v);
    v
}

fn random_vec(size: usize) -> Vec<u8> {
    let mut v = vec![0_u8; size];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut v);
    v
}

fn get_psks_count(params: &NoiseParams) -> usize {
    params
        .handshake
        .modifiers
        .list
        .iter()
        .filter(|m| matches!(m, HandshakeModifier::Psk(_)))
        .count()
}

#[allow(clippy::too_many_lines)]
fn generate_vector(params: NoiseParams) -> TestVector {
    let prologue = b"There is no right and wrong. There's only fun and boring.".to_vec();
    let (mut psks, mut psks_hex) = (vec![], vec![]);
    let mut init_b: Builder<'_> = Builder::new(params.clone());
    let mut resp_b: Builder<'_> = Builder::new(params.clone());
    let is = init_b.generate_keypair().unwrap();
    let ie = init_b.generate_keypair().unwrap();
    let rs = resp_b.generate_keypair().unwrap();
    let re = resp_b.generate_keypair().unwrap();

    for _ in 0..get_psks_count(&params) {
        let v = random_slice::<32>();
        psks_hex.push(v.into());
        psks.push(v);
    }

    let mut psk_index = 0;
    for modifier in params.handshake.modifiers.list {
        if let HandshakeModifier::Psk(n) = modifier {
            init_b = init_b.psk(n, &psks[psk_index]).unwrap();
            resp_b = resp_b.psk(n, &psks[psk_index]).unwrap();
            psk_index += 1;
        }
    }
    init_b = init_b.fixed_ephemeral_key_for_testing_only(&ie.private);
    init_b = init_b.prologue(&prologue).unwrap();
    if params.handshake.pattern.needs_local_static_key(true) {
        init_b = init_b.local_private_key(&is.private).unwrap();
    }
    if params.handshake.pattern.need_known_remote_pubkey(true) {
        init_b = init_b.remote_public_key(&rs.public).unwrap();
    }

    resp_b = resp_b.fixed_ephemeral_key_for_testing_only(&re.private);
    resp_b = resp_b.prologue(&prologue).unwrap();
    if params.handshake.pattern.needs_local_static_key(false) {
        resp_b = resp_b.local_private_key(&rs.private).unwrap();
    }
    if params.handshake.pattern.need_known_remote_pubkey(false) {
        resp_b = resp_b.remote_public_key(&is.public).unwrap();
    }

    let mut init = init_b.build_initiator().unwrap();
    let mut resp = resp_b.build_responder().unwrap();

    let (mut ibuf, mut obuf) =
        (vec![0_u8; 65535].into_boxed_slice(), vec![0_u8; 65535].into_boxed_slice());
    let mut messages = vec![];
    let mut i = 0;
    while !(init.is_handshake_finished() && resp.is_handshake_finished()) {
        let payload = random_vec(32);
        let len = init.write_message(&payload, &mut ibuf).unwrap();
        messages.push(TestMessage {
            payload:    payload.clone().into(),
            ciphertext: ibuf[..len].to_vec().into(),
        });
        i += 1;
        let _ = resp.read_message(&ibuf[..len], &mut obuf).unwrap();

        if init.is_handshake_finished() && resp.is_handshake_finished() {
            break;
        }

        let payload = random_vec(32);
        let len = resp.write_message(&payload, &mut ibuf).unwrap();
        messages.push(TestMessage {
            payload:    payload.clone().into(),
            ciphertext: ibuf[..len].to_vec().into(),
        });
        i += 1;
        let _ = init.read_message(&ibuf[..len], &mut obuf).unwrap();
    }

    let (mut init_tr, mut resp_tr) =
        (init.into_transport_mode().unwrap(), resp.into_transport_mode().unwrap());

    let (init, resp) = if params.handshake.pattern.is_oneway() || i % 2 == 0 {
        (&mut init_tr, &mut resp_tr)
    } else {
        (&mut resp_tr, &mut init_tr)
    };

    let payload = random_vec(32);
    let len = init.write_message(&payload, &mut ibuf).unwrap();
    messages.push(TestMessage {
        payload:    payload.clone().into(),
        ciphertext: ibuf[..len].to_vec().into(),
    });

    if !params.handshake.pattern.is_oneway() {
        let payload = random_vec(32);
        let len = resp.write_message(&payload, &mut obuf).unwrap();
        messages.push(TestMessage {
            payload:    payload.clone().into(),
            ciphertext: obuf[..len].to_vec().into(),
        });
    }

    let init_static = if params.handshake.pattern.needs_local_static_key(true) {
        Some(is.private.clone().into())
    } else {
        None
    };
    let resp_static = if params.handshake.pattern.needs_local_static_key(false) {
        Some(rs.private.clone().into())
    } else {
        None
    };
    let init_remote_static = if params.handshake.pattern.need_known_remote_pubkey(true) {
        Some(rs.public.clone().into())
    } else {
        None
    };
    let resp_remote_static = if params.handshake.pattern.need_known_remote_pubkey(false) {
        Some(is.public.clone().into())
    } else {
        None
    };

    TestVector {
        name: None,
        protocol_name: params.name,
        hybrid: None,
        fail: None,
        fallback: None,
        fallback_pattern: None,
        init_prologue: prologue.clone().into(),
        init_psks: Some(psks_hex.clone()),
        init_static,
        init_ephemeral: Some(ie.private.clone().into()),
        init_remote_static,
        resp_prologue: prologue.clone().into(),
        resp_psks: Some(psks_hex.clone()),
        resp_static,
        resp_ephemeral: Some(re.private.clone().into()),
        resp_remote_static,
        messages,
    }
}

fn generate_vector_set(official: bool) -> TestVectors {
    let mut handshakes =
        SUPPORTED_HANDSHAKE_PATTERNS.iter().map(|p| p.as_str()).collect::<Vec<&'static str>>();
    handshakes.extend_from_slice(&[
        "NNpsk0+psk2",
        "NXpsk0+psk1+psk2",
        "XNpsk1+psk3",
        "XKpsk0+psk3",
        "KNpsk1+psk2",
        "KKpsk0+psk2",
        "INpsk1+psk2",
        "IKpsk0+psk2",
        "IXpsk0+psk2",
        "XXpsk0+psk1",
        "XXpsk0+psk2",
        "XXpsk0+psk3",
        "XXpsk0+psk1+psk2+psk3",
    ]);
    let dhs = if official { vec!["25519"] } else { vec!["P256"] };
    let ciphers = if official { vec!["ChaChaPoly", "AESGCM"] } else { vec!["XChaChaPoly"] };
    let hashes = vec!["BLAKE2s", "BLAKE2b", "SHA256", "SHA512"];

    let mut vectors = vec![];

    for handshake in &handshakes {
        for dh in &dhs {
            for cipher in &ciphers {
                for hash in &hashes {
                    let protocol_name = format!("Noise_{handshake}_{dh}_{cipher}_{hash}");
                    let protocol = protocol_name.parse().unwrap();
                    vectors.push(generate_vector(protocol));
                }
            }
        }
    }
    TestVectors { vectors }
}

#[test]
fn test_vectors_cacophony() {
    test_vectors_from_json(include_str!("vectors/cacophony.txt"));
}

/// These are the test vectors for all the official "spec 34" features.
#[test]
fn test_vectors_snow() {
    let file_res = OpenOptions::new().write(true).create_new(true).open("tests/vectors/snow.txt");
    if let Ok(mut file) = file_res {
        serde_json::to_writer_pretty(&mut file, &generate_vector_set(true)).unwrap();
    }
    let mut file = File::open("tests/vectors/snow.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    test_vectors_from_json(&contents);
}

/// These are the test vectors for non-standard features.
#[test]
fn test_vectors_snow_extended() {
    let file_res =
        OpenOptions::new().write(true).create_new(true).open("tests/vectors/snow-extended.txt");
    if let Ok(mut file) = file_res {
        serde_json::to_writer_pretty(&mut file, &generate_vector_set(false)).unwrap();
    }
    let mut file = File::open("tests/vectors/snow-extended.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    test_vectors_from_json(&contents);
}
