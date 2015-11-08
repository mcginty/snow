extern crate noiseref;

use noiseref::*;

#[test]
fn it_works() {
    let mut rng = RandomOs::new();
    let s_i = Dh25519::generate(&mut rng);
    let s_r = Dh25519::generate(&mut rng);
    let mut h_i = HandshakeState::<NoiseXX, Dh25519, CipherAESGCM, HashSHA256, RandomOs>::new(true, Some(s_i), None, None, None);
    let mut h_r = HandshakeState::<NoiseXX, Dh25519, CipherAESGCM, HashSHA256, RandomOs>::new(false, Some(s_r), None, None, None);

    let payload_in_0 = "abcdef".as_bytes();
    let mut buffer = [0u8; 1024];
    let (msg_0_len_in, _) = h_i.write_message(&payload_in_0, &mut buffer);
    assert!(msg_0_len_in == 38);

    let mut payload_out_0 = [0u8; 1024];
    let result = h_r.read_message(&buffer[..msg_0_len_in], &mut payload_out_0);
    let (msg_0_len_out, _) = result.unwrap(); 
    assert!(payload_in_0.len() == msg_0_len_out);
    //assert!(payload_in_0 == payload_out_0);

}
