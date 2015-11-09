extern crate noiseref;
extern crate rustc_serialize;

use noiseref::*;
use self::rustc_serialize::hex::{ToHex};


struct RandomInc {
    next_byte: u8
}

impl Random for RandomInc {

    fn new() -> RandomInc {
        RandomInc {next_byte: 0}
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for count in 0..out.len() {
            out[count] = self.next_byte;
            if self.next_byte == 255 {
                self.next_byte = 0;
            }
            else {
                self.next_byte += 1;
            }
        }
    }
}

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}

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


    // Noise_N test
    {
        type  HS = HandshakeState<NoiseN, Dh25519, CipherAESGCM, HashSHA256, RandomInc>;
        let mut rng = RandomInc::new();
        let static_r = Dh25519::generate(&mut rng);
        let mut static_pubkey = [0u8; 32];
        copy_memory(static_r.pubkey(), &mut static_pubkey);

        let mut h = HS::new(rng, true, None, None, Some(static_pubkey), None);
        let mut buffer = [0u8; 48];
        assert!(h.write_message(&[0u8;0], &mut buffer).0 == 48);
        assert!(buffer.to_hex() == "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254a9f57a83ac259e1caf3f2da6ff5264d5");
    }

    // Noise_X test
    {
        type  HS = HandshakeState<NoiseX, Dh25519, CipherChaChaPoly, HashSHA256, RandomInc>;
        let mut rng = RandomInc::new();
        let static_i = Dh25519::generate(&mut rng);
        let static_r = Dh25519::generate(&mut rng);
        let mut static_pubkey = [0u8; 32];
        copy_memory(static_r.pubkey(), &mut static_pubkey);

        let mut h = HS::new(rng, true, Some(static_i), None, Some(static_pubkey), None);
        let mut buffer = [0u8; 96];
        assert!(h.write_message(&[0u8;0], &mut buffer).0 == 96);
        assert!(buffer.to_hex() == "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89a\
                                    f85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d\
                                    7f180a6e9bbcc0300ba7c6e6761e17110a61d92f4b18da15d5a27f7aace013e2bc");
    } 

    // Noise_NN test
    {
        type  HS = HandshakeState<NoiseNN, Dh25519, CipherAESGCM, HashSHA512, RandomInc>;
        let rng_i = RandomInc::new();
        let mut rng_r = RandomInc::new();
        rng_r.next_byte = 1; 

        let mut h_i = HS::new(rng_i, true, None, None, None, None);
        let mut h_r = HS::new(rng_r, false, None, None, None, None);
        let mut buffer_msg = [0u8; 64];
        let mut buffer_out = [0u8; 10];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 35);
        assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 52);
        assert!(h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        assert!(buffer_msg[..52].to_hex() == "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c\
                                              7c5e4dc954a1f101cdd5a583423fbae23fef0b49ab");
    } 

    // Noise_XX test
    {
        type  HS = HandshakeState<NoiseXX, Dh25519, CipherAESGCM, HashSHA256, RandomInc>;
        let mut rng_i = RandomInc::new();
        let mut rng_r = RandomInc::new();
        rng_r.next_byte = 1; 

        let static_i = Dh25519::generate(&mut rng_i);
        let static_r = Dh25519::generate(&mut rng_r);
        let mut static_pubkey = [0u8; 32];
        copy_memory(static_r.pubkey(), &mut static_pubkey);

        let mut h_i = HS::new(rng_i, true, Some(static_i), None, None, None);
        let mut h_r = HS::new(rng_r, false, Some(static_r), None, None, None);
        let mut buffer_msg = [0u8; 200];
        let mut buffer_out = [0u8; 200];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 35);
        assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 100);
        assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).0 == 64);
        assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

        //println!("{}", buffer_msg[..64].to_hex());
        assert!(buffer_msg[..64].to_hex() == "8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb\
                                              50a2ca2f225ac01ab7de84f2f15bb8ec5e26da133c677ea97cfc2b14f77a15d3ade3c");
                                              
    } 

    // Noise_IK test
    {
        type  HS = HandshakeState<NoiseIK, Dh25519, CipherAESGCM, HashSHA256, RandomInc>;
        let mut rng_i = RandomInc::new();
        let mut rng_r = RandomInc::new();
        rng_r.next_byte = 1; 

        let static_i = Dh25519::generate(&mut rng_i);
        let static_r = Dh25519::generate(&mut rng_r);
        let mut static_pubkey = [0u8; 32];
        copy_memory(static_r.pubkey(), &mut static_pubkey);

        let mut h_i = HS::new(rng_i, true, Some(static_i), None, Some(static_pubkey), None);
        let mut h_r = HS::new(rng_r, false, Some(static_r), None, None, None);
        let mut buffer_msg = [0u8; 200];
        let mut buffer_out = [0u8; 200];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 99);
        assert!(h_r.read_message(&buffer_msg[..99], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 68);
        assert!(h_i.read_message(&buffer_msg[..68], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        //println!("{}", buffer_msg[..68].to_hex());
        assert!(buffer_msg[..68].to_hex() == "5a491c3d8524aee516e7edccba51433ebe651002f0f79fd79dc6a4bf65ecd7b1\
                                              164dd506e33d03606ebf3a34e88f2b3b7555a941573231837bee4b47054e765508b2aca6");
    } 

    // Noise_XE test
    {
        type  HS = HandshakeState<NoiseXE, Dh25519, CipherChaChaPoly, HashBLAKE2b, RandomInc>;
        let mut rng_i = RandomInc::new();
        let mut rng_r = RandomInc::new();
        rng_r.next_byte = 1; 

        let static_i = Dh25519::generate(&mut rng_i);
        let static_r = Dh25519::generate(&mut rng_r);
        let eph_r = Dh25519::generate(&mut rng_r);
        let mut static_pubkey = [0u8; 32];
        copy_memory(static_r.pubkey(), &mut static_pubkey);
        let mut eph_pubkey = [0u8; 32];
        copy_memory(eph_r.pubkey(), &mut eph_pubkey);

        let mut h_i = HS::new(rng_i, true, Some(static_i), None, Some(static_pubkey), Some(eph_pubkey));
        let mut h_r = HS::new(rng_r, false, Some(static_r), Some(eph_r), None, None);
        let mut buffer_msg = [0u8; 200];
        let mut buffer_out = [0u8; 200];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 51);
        assert!(h_r.read_message(&buffer_msg[..51], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 68);
        assert!(h_i.read_message(&buffer_msg[..68], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).0 == 64);
        assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

        //println!("{}", buffer_msg[..64].to_hex());
        assert!(buffer_msg[..64].to_hex() == "08439f380b6f128a1465840d558f06abb1141cf5708a9dcf573d6e4fae01f90f\
                                              8987d8dff8fa2fba7cd7a811496f18e93ac7142fb5297e0737497bc66bb8b3f8");
    } 
}
