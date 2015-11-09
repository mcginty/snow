extern crate noiseref;
extern crate rustc_serialize;

use noiseref::*;
use self::rustc_serialize::hex::{ToHex};

#[test]
fn it_works() {

    // Noise_XX round-trip randomized test
    {

        type  HS = HandshakeState<NoiseXX, Dh25519, CipherAESGCM, HashSHA256, RandomOs>;

        let mut rng_i = RandomOs::new();
        let mut rng_r = RandomOs::new();
        let static_i = Dh25519::generate(&mut rng_i);
        let static_r = Dh25519::generate(&mut rng_r);
        let mut h_i = HS::new(rng_i, true, Some(static_i), None, None, None);
        let mut h_r = HS::new(rng_r, false, Some(static_r), None, None, None);

        let mut buffer = [0u8; 1024];

        // -> e
        let payload_0 = "abcdef".as_bytes();
        let (msg_0_len, _) = h_i.write_message(&payload_0, &mut buffer);
        assert!(msg_0_len == 38);

        let mut payload_0_out = [0u8; 1024];
        let result_0 = h_r.read_message(&buffer[..msg_0_len], &mut payload_0_out);
        let (payload_0_out_len, _) = result_0.unwrap(); 
        assert!(payload_0.len() == payload_0_out_len);
        assert!(payload_0.to_hex() == payload_0_out[..payload_0_out_len].to_hex());


        // <- e, dhee, s, dhse
        let payload_1 = [0u8; 0]; 
        let (msg_1_len, _) = h_r.write_message(&payload_1, &mut buffer);
        assert!(msg_1_len == 96);

        let mut payload_1_out = [0u8; 1024];
        let result_1 = h_i.read_message(&buffer[..msg_1_len], &mut payload_1_out);
        let (payload_1_out_len, _) = result_1.unwrap(); 
        assert!(payload_1.len() == payload_1_out_len);


        // -> s, dhse
        let payload_2 = "0123456789012345678901234567890123456789012345678901234567890123456789".as_bytes();
        let (msg_2_len, cipher_states_i_option) = h_i.write_message(&payload_2, &mut buffer);
        assert!(msg_2_len == 134);

        let mut payload_2_out = [0u8; 1024];
        let result_2 = h_r.read_message(&buffer[..msg_2_len], &mut payload_2_out);
        let (payload_2_out_len, cipher_states_r_option) = result_2.unwrap(); 
        assert!(payload_2.len() == payload_2_out_len);
        assert!(payload_2.to_hex() == payload_2_out[..payload_2_out_len].to_hex());

        let mut cipher_states_i = cipher_states_i_option.unwrap();
        let mut cipher_states_r = cipher_states_r_option.unwrap();

        // transport message I -> R
        let payload_3 = "wubba".as_bytes();
        cipher_states_i.0.encrypt(&payload_3, &mut buffer);

        let mut payload_3_out = [0u8; 1024];
        assert!(cipher_states_r.1.decrypt(&buffer[..21], &mut payload_3_out));
        assert!(payload_3.to_hex() == payload_3_out[..5].to_hex());

        // transport message I -> R again
        let payload_4 = "aleph".as_bytes();
        cipher_states_i.0.encrypt(&payload_4, &mut buffer);

        let mut payload_4_out = [0u8; 1024];
        assert!(cipher_states_r.1.decrypt(&buffer[..21], &mut payload_4_out));
        assert!(payload_4.to_hex() == payload_4_out[..5].to_hex());

        // transport message R <- I
        let payload_5 = "worri".as_bytes();
        cipher_states_i.0.encrypt(&payload_5, &mut buffer);

        let mut payload_5_out = [0u8; 1024];
        assert!(cipher_states_r.1.decrypt(&buffer[..21], &mut payload_5_out));
        assert!(payload_5.to_hex() == payload_5_out[..5].to_hex());
    } 



    {

    }
}
