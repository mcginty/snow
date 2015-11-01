extern crate noiseref;

use noiseref::*;

#[test]
fn it_works() {
    let s_i = Some(Dh25519::generate());
    let s_r = Some(Dh25519::generate());
    let handshake_name = "Noise_XX_25519_AESGCM_SHA256";
    let mut h_i = HandshakeState::<Dh25519, CipherAESGCM, HashSHA256>::new(&handshake_name.as_bytes(), s_i, None, None, None);
    let mut h_r = HandshakeState::<Dh25519, CipherAESGCM, HashSHA256>::new(&handshake_name.as_bytes(), s_r, None, None, None);

    let payload_in_0 = "abcdef".as_bytes();
    let mut buffer = [0u8; 1024];
    let (msg_0_len_in, _) = h_i.write_message(&[Token::E], false, &payload_in_0, &mut buffer);
    assert!(msg_0_len_in == 38);

    let mut payload_out_0 = [0u8; 1024];
    let result = h_r.read_message(&[Token::E], false, &buffer[..msg_0_len_in], &mut payload_out_0);
    let (msg_0_len_out, _) = result.unwrap(); 
    assert!(payload_in_0.len() == msg_0_len_out);
    //assert!(payload_in_0 == payload_out_0);

}
