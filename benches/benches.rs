#![feature(test)]

extern crate test;
extern crate snow;

use snow::*;
use snow::params::*;
use snow::types::*;
use snow::wrappers::crypto_wrapper::Dh25519;
use snow::wrappers::rand_wrapper::RandomOs;
use test::Bencher;

const MSG_SIZE: usize = 4096;

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}


#[bench]
fn bench_xx_handshake(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);


    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let pattern: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
        let mut h_i = NoiseBuilder::new(pattern.clone())
            .local_private_key(static_i.privkey())
            .build_initiator().unwrap();
        let mut h_r = NoiseBuilder::new(pattern)
            .local_private_key(static_r.privkey())
            .build_responder().unwrap();

        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        let mut buffer_out = [0u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        let len = h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_nn_handshake(b: &mut Bencher) {
    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2b";
        let mut h_i = NoiseBuilder::new(pattern.parse().unwrap())
            .build_initiator().unwrap();
        let mut h_r = NoiseBuilder::new(pattern.parse().unwrap())
            .build_responder().unwrap();

        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        let mut buffer_out = [0u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_write_throughput_aesgcm_sha256(b: &mut Bencher) {
    b.bytes = MSG_SIZE as u64;
    static PATTERN: &'static str = "Noise_NN_25519_AESGCM_SHA256";

    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();

    b.iter(move || {
        let _ = h_i.write_message(&buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_read_write_throughput_aesgcm_sha256(b: &mut Bencher) {
    b.bytes = (MSG_SIZE * 2) as u64;
    static PATTERN: &'static str = "Noise_NN_25519_AESGCM_SHA256";

    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    b.iter(move || {
        let len = h_i.write_message(&buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
        let _ = h_r.read_message(&buffer_out[..len], &mut buffer_msg).unwrap();
    });
}

#[bench]
fn bench_write_throughput_chachapoly_blake2s(b: &mut Bencher) {
    b.bytes = MSG_SIZE as u64;
    static PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();

    b.iter(move || {
        let _ = h_i.write_message(&buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_read_write_throughput_chachapoly_blake2s(b: &mut Bencher) {
    b.bytes = (MSG_SIZE * 2) as u64;
    static PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    let len = h_i.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    let len = h_r.write_message(&[0u8; 0], &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    b.iter(move || {
        let len = h_i.write_message(&buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
        let _ = h_r.read_message(&buffer_out[..len], &mut buffer_msg).unwrap();
    });
}

#[bench]
fn bench_new_builder_with_key(b: &mut Bencher) {
    let static_i:Dh25519 = Default::default();
    let privkey = static_i.privkey();
    b.iter(move || {
        NoiseBuilder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .local_private_key(privkey)
                .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_skeleton(b: &mut Bencher) {
    b.iter(move || {
        NoiseBuilder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .build_initiator().unwrap();
    });
}
