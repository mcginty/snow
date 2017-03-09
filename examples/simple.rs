//! This is a barebones TCP Client/Server that establishes a Noise_NN session, and sends
//! an important message across the wire.
//!
//! # Usage
//! Run the server a-like-a-so `cargo run --example simple -- -s`, then run the client
//! as `cargo run --example simple` to see the magic happen.

extern crate clap;
extern crate snow;

use clap::App;
use snow::{NoiseBuilder, NoiseParams, NoiseSessionState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn main() {
    let matches = App::new("simple").args_from_usage("-s --server 'Server mode'").get_matches();

    let params = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    if matches.is_present("server") {
        run_server(params);
    } else {
        run_client(params);
    }
    println!("all done!");
}

fn run_server(params: NoiseParams) {
    let mut buf = vec![0u8; 65535];

    // Initialize our responder NoiseSession using a builder.
    let mut noise = NoiseBuilder::new(params).build_responder().unwrap();

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:9999");
    let (mut stream, _) = TcpListener::bind("127.0.0.1:9999").unwrap().accept().unwrap();

    // We're acting as the responder, so the first message is sent from the client.
    noise.read_message(&recv(&mut stream), &mut buf).unwrap();

    // Respond, thereby completing the handshake for NN, which is 1RTT.
    let len = noise.write_message(&[0u8; 0], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // Transition the state machine into transport mode now that the handshake is complete.
    let mut noise = noise.into_transport_mode().unwrap();

    let len = noise.read_message(&recv(&mut stream), &mut buf).unwrap();
    println!("client said: {}", String::from_utf8_lossy(&buf[..len]));
}

fn run_client(params: NoiseParams) {
    let mut buf = vec![0u8; 65535];

    // Initialize our initiator NoiseSession using a builder.
    let mut noise = NoiseBuilder::new(params).build_initiator().unwrap();

    // Connect to our server, which is hopefully listening.
    let mut stream = TcpStream::connect("127.0.0.1:9999").unwrap();
    println!("connected...");

    // We're the initiator, so we're responsible for sending the first message.
    let len = noise.write_message(&[0u8; 0], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // Receive response, thereby completing the handshake for NN
    noise.read_message(&recv(&mut stream), &mut buf).unwrap();

    // Transition the state machine into transport mode now that the handshake is complete.
    let mut noise = noise.into_transport_mode().unwrap();
    println!("session established...");

    // Get to the important business of sending secured data.
    let len = noise.write_message("HACK THE PLANET".as_bytes(), &mut buf).unwrap();
    send(&mut stream, &buf[..len]);
    println!("notified server of intent to hack planet.");
}

/// Hyper-basic stream transort receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf).unwrap();
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).unwrap();
    msg
}

/// Hyper-basic stream transort sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    let mut msg_len_buf = [0u8; 2];
    msg_len_buf[0] = (buf.len() >> 8) as u8;
    msg_len_buf[1] = (buf.len() & 0xff) as u8;
    stream.write_all(&msg_len_buf).unwrap();
    stream.write_all(buf).unwrap();
}
