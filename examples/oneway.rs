#![cfg_attr(
    not(any(feature = "default-resolver", feature = "ring-accelerated",)),
    allow(dead_code, unused_extern_crates, unused_imports)
)]
//! This is a barebones TCP Client/Server that establishes a `Noise_X` session, and sends
//! an important message across the wire.
//!
//! # Usage
//! Run the server a-like-a-so `cargo run --example oneway -- -s`, then run the client
//! as `cargo run --example oneway` to see the magic happen.

use hex::FromHex;
use lazy_static::lazy_static;
use snow::{params::NoiseParams, Builder, Keypair};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};

static SECRET: &[u8; 32] = b"i don't care for fidget spinners";
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    // The responder key is static in this example because the X pattern means
    // the initiator has pre-handshake knowledge of the responder's public key
    // (and of course both share the same psk `SECRET`)
    static ref RESPONDER: Keypair = Keypair {
        private: Vec::from_hex("52fbe3721d1adbe312d270ca2db5ce5bd39ddc206075f3a8f06d422619c8eb5d").expect("valid hex"),
        public: Vec::from_hex("435ce8a8415ccd44de5e207581ac7207b416683028bcaecc9eb38d944e6f900c").expect("valid hex"),
    };
}

#[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn main() {
    let server_mode =
        std::env::args().next_back().map_or(true, |arg| arg == "-s" || arg == "--server");

    if server_mode {
        run_server(&RESPONDER.private, SECRET);
    } else {
        run_client(&RESPONDER.public, SECRET);
    }
    println!("all done.");
}

#[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn run_server(private_key: &[u8], psk: &[u8; 32]) {
    let mut buf = vec![0u8; 65535];

    // Initialize our responder using a builder.
    let builder = Builder::new(PARAMS.clone());
    let mut noise = builder
        .local_private_key(private_key)
        .unwrap()
        .psk(1, psk)
        .unwrap()
        .build_responder()
        .unwrap();

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:9999");
    let (mut stream, _) = TcpListener::bind("127.0.0.1:9999").unwrap().accept().unwrap();

    // <- e, es, s, ss
    noise.read_message(&recv(&mut stream).unwrap(), &mut buf).unwrap();

    // This is a oneway handshake - the server does not have to send anything

    // The remote static key (of the initiator) is now known
    let client = hex::encode(noise.get_remote_static().unwrap());

    // Transition the state machine into transport mode now that the handshake is complete.
    let mut noise = noise.into_transport_mode().unwrap();

    while let Ok(msg) = recv(&mut stream) {
        let len = noise.read_message(&msg, &mut buf).unwrap();
        println!("{client} said: {}", String::from_utf8_lossy(&buf[..len]));
    }
    println!("connection closed.");
}

#[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn run_client(responder_public_key: &[u8], psk: &[u8; 32]) {
    let mut buf = vec![0u8; 65535];

    // Initialize our initiator using a builder.
    let builder = Builder::new(PARAMS.clone());
    let private_key = &builder.generate_keypair().unwrap().private;
    let mut noise = builder
        .local_private_key(private_key)
        .unwrap()
        .remote_public_key(responder_public_key)
        .unwrap()
        .psk(1, psk)
        .unwrap()
        .build_initiator()
        .unwrap();

    // Connect to our server, which is hopefully listening.
    let mut stream = TcpStream::connect("127.0.0.1:9999").unwrap();
    println!("connected...");

    // -> e, es, s, ss
    let len = noise.write_message(&[], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // This is a oneway handshake - the respnder must not send anything

    let mut noise = noise.into_transport_mode().unwrap();
    println!("session established...");

    // Get to the important business of sending secured data.
    for _ in 0..10 {
        let len = noise.write_message(b"HACK THE PLANET", &mut buf).unwrap();
        send(&mut stream, &buf[..len]);
    }
    println!("notified server of intent to hack planet.");
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf)?;
    let msg_len = usize::from(u16::from_be_bytes(msg_len_buf));
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..])?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    let len = u16::try_from(buf.len()).expect("message too large");
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(buf).unwrap();
}

#[cfg(not(any(feature = "default-resolver", feature = "ring-accelerated")))]
fn main() {
    panic!("Example must be compiled with some cryptographic provider.");
}
