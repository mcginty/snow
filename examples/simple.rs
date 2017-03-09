extern crate clap;
extern crate snow;

use clap::App;
use snow::*;
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
    let mut noise = NoiseBuilder::new(params).build_responder().unwrap();
    let mut buf = vec![0u8; 65535];

    let listener = TcpListener::bind("127.0.0.1:9999").unwrap();
    println!("listening on 127.0.0.1:9999");
    let (mut stream, _) = listener.accept().unwrap();

    // get first message from intiator
    noise.read_message(&recv(&mut stream)[..], &mut buf).unwrap();

    // respond, completing the handshake for NN
    let len = noise.write_message(&[0u8; 0], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    if noise.is_handshake_finished() {
        println!("session established...");
    }

    let mut noise = noise.into_transport_mode().unwrap();

    let len = noise.read_message(&recv(&mut stream)[..], &mut buf).unwrap();
    println!("client said: {}", String::from_utf8_lossy(&buf[..len]));
}

fn run_client(params: NoiseParams) {
    let mut noise = NoiseBuilder::new(params).build_initiator().unwrap();
    let mut buf = vec![0u8; 65535];
    let mut stream = TcpStream::connect("127.0.0.1:9999").unwrap();
    println!("connected...");

    // initiator sends the first message
    let len = noise.write_message(&[0u8; 0], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // get response, completing the handshake for NN
    let message = recv(&mut stream);
    noise.read_message(&message[..], &mut buf).unwrap();

    if noise.is_handshake_finished() {
        println!("session established...");
    }
    let mut noise = noise.into_transport_mode().unwrap();

    let len = noise.write_message("HACK THE PLANET".as_bytes(), &mut buf).unwrap();
    send(&mut stream, &buf[..len]);
    println!("notified server of intent to hack planet.");
}

fn recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf).unwrap();
    let mut msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).unwrap();
    msg
}

fn send(stream: &mut TcpStream, buf: &[u8]) {
    let mut msg_len_buf = [0u8; 2];
    msg_len_buf[0] = (buf.len() >> 8) as u8;
    msg_len_buf[1] = (buf.len() & 0xff) as u8;
    stream.write_all(&msg_len_buf).unwrap();
    stream.write_all(buf).unwrap();
}
