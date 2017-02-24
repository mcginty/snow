#![feature(test)]

extern crate test;
extern crate screech;
extern crate rustc_serialize;

use screech::*;
use self::rustc_serialize::hex::ToHex;
use test::Bencher;

const MSG_SIZE: usize = 4096;

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}


#[bench]
fn bench_xx_handshake_punk(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);


    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
        let mut h_i = NoiseBuilder::new(pattern.parse().unwrap())
            .local_private_key(static_i.privkey())
            .build_initiator().unwrap();
        let mut h_r = NoiseBuilder::new(pattern.parse().unwrap())
            .local_private_key(static_r.privkey())
            .build_responder().unwrap();

        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        let mut buffer_out = [0u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();
        h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();
        h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_kk_handshake_punk(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);


    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let pattern = "Noise_IN_25519_ChaChaPoly_BLAKE2b";
        let mut h_i = NoiseBuilder::new(pattern.parse().unwrap())
            .local_private_key(static_i.privkey())
            .build_initiator().unwrap();
        let mut h_r = NoiseBuilder::new(pattern.parse().unwrap())
            .local_private_key(static_r.privkey())
            .build_responder().unwrap();

        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        let mut buffer_out = [0u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();
        h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_full_handshake_nist(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);

    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        static PATTERN: &'static str = "Noise_XX_25519_AESGCM_SHA256";
        let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
            .local_private_key(static_i.privkey())
            .build_initiator().unwrap();
        let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
            .local_private_key(static_r.privkey())
            .build_responder().unwrap();

        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        let mut buffer_out = [0u8; MSG_SIZE * 2];
        h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();

        h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();

        h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0;
        h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_read_throughput_punk(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);


    b.bytes = MSG_SIZE as u64;
    static PATTERN: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();
    h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();
    h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap();

    assert!(h_i.is_handshake_finished());
    let mut ciphers = h_i.transition();
    ciphers.0.encrypt(&buffer_msg[..MSG_SIZE], &mut buffer_out);

    b.iter(move || {
        ciphers.0.decrypt(&buffer_out[..MSG_SIZE], &mut buffer_msg);
    });
}

#[bench]
fn bench_write_throughput_punk(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);


    b.bytes = MSG_SIZE as u64;
    static PATTERN: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    let mut h_i = NoiseBuilder::new(PATTERN.parse().unwrap())
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(PATTERN.parse().unwrap())
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();
    h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();
    h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap();

    assert!(h_i.is_handshake_finished());
    let mut ciphers = h_i.transition();

    b.iter(move || {
        ciphers.0.encrypt(&buffer_msg[..MSG_SIZE], &mut buffer_out);
    });
}

#[bench]
fn bench_new_builder_from_string_with_key(b: &mut Bencher) {
    let static_i:Dh25519 = Default::default();
    let privkey = static_i.privkey();
    b.iter(move || {
        NoiseBuilder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .local_private_key(privkey)
                .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_string_skeleton(b: &mut Bencher) {
    b.iter(move || {
        NoiseBuilder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_params_skeleton(b: &mut Bencher) {
    b.iter(move || {
        let init = NoiseParams::new(BaseChoice::Noise,
                                    HandshakePattern::NN,
                                    DHChoice::Curve25519,
                                    CipherChoice::ChaChaPoly,
                                    HashChoice::SHA256);
        NoiseBuilder::new(init)
            .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_params_with_key(b: &mut Bencher) {
    let static_i:Dh25519 = Default::default();
    let privkey = static_i.privkey();
    b.iter(move || {
        let init = NoiseParams::new(BaseChoice::Noise,
                                    HandshakePattern::NN,
                                    DHChoice::Curve25519,
                                    CipherChoice::ChaChaPoly,
                                    HashChoice::SHA256);
        NoiseBuilder::new(init)
            .local_private_key(privkey)
            .build_initiator().unwrap();
    });
}
