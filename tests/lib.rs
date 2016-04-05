extern crate screech;
extern crate rustc_serialize;

use screech::*;
use self::rustc_serialize::hex::{FromHex, ToHex};


struct RandomInc {
    next_byte: u8
}

impl Default for RandomInc {

    fn default() -> RandomInc {
        RandomInc {next_byte: 0}
    }
}

impl RandomType for RandomInc {

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
fn test1() {

    // Noise_N test
    {    
        let mut static_r:Dh25519 = Default::default();

        let mut owner : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA256> = Default::default();
        static_r.generate(&mut owner.rng);
        owner.set_rs(static_r.pubkey());

        let mut cipherstate1 : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2 : CipherState<CipherAESGCM> = Default::default();

        let mut h = HandshakeState::new_from_owner(&mut owner,
                                                   true,
                                                   HandshakePattern::N,
                                                   &[0u8; 0],
                                                   None,
                                                   &mut cipherstate1,
                                                   &mut cipherstate2);


        let mut buffer = [0u8; 48];
        assert!(h.write_message(&[0u8;0], &mut buffer).0 == 48);
        //println!("{}", buffer.to_hex());
        assert!(buffer.to_hex() =="358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662548331a3d1e93b490263abc7a4633867f4"); 

    }

    // Noise_X test
    {
        let mut static_i:Dh25519 = Default::default();
        let mut static_r:Dh25519 = Default::default();

        let mut owner : HandshakeCryptoOwner<RandomInc, Dh25519, CipherChaChaPoly, HashSHA256> = Default::default();
        static_i.generate(&mut owner.rng);
        static_r.generate(&mut owner.rng);

        owner.set_s(static_i);
        owner.set_rs(static_r.pubkey());

        let mut cipherstate1 : CipherState<CipherChaChaPoly> = Default::default();
        let mut cipherstate2 : CipherState<CipherChaChaPoly> = Default::default();

        let mut h = HandshakeState::new_from_owner(&mut owner,
                            true,
                            HandshakePattern::X,
                            &[0u8; 0],
                            None,
                            &mut cipherstate1,
                            &mut cipherstate2);

        let mut buffer = [0u8; 96];
        assert!(h.write_message(&[0u8;0], &mut buffer).0 == 96);
        //println!("{}", buffer.to_hex());
        assert!(buffer.to_hex() == "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d7f2cf1b1c5af10e38a09a9bb7e3b1d589a99492cc50293eaa1f3f391b59bb6990d");
    } 

    // Noise_NN test
    {
        let mut owner_i : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA512> = Default::default();
        let mut owner_r : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA512> = Default::default();

        owner_r.rng.next_byte = 1;

        let mut cipherstate1_i : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_i : CipherState<CipherAESGCM> = Default::default();

        let mut cipherstate1_r : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_r : CipherState<CipherAESGCM> = Default::default();

        let mut h_i = HandshakeState::new_from_owner(&mut owner_i,
                            true,
                            HandshakePattern::NN,
                            &[0u8; 0],
                            None,
                            &mut cipherstate1_i,
                            &mut cipherstate2_i);

        let mut h_r = HandshakeState::new_from_owner(&mut owner_r,
                            false,
                            HandshakePattern::NN,
                            &[0u8; 0],
                            None,
                            &mut cipherstate1_r,
                            &mut cipherstate2_r);

        let mut buffer_msg = [0u8; 64];
        let mut buffer_out = [0u8; 10];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 35);
        assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 52);
        assert!(h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        //println!("{}", buffer_msg[..52].to_hex());
        assert!(buffer_msg[..52].to_hex() == "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0"); 
    } 

    // Noise_XX test
    {
        let mut static_i:Dh25519 = Default::default();
        let mut static_r:Dh25519 = Default::default();

        let mut owner_i : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA256> = Default::default();
        let mut owner_r : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA256> = Default::default();

        owner_r.rng.next_byte = 1;
        static_i.generate(&mut owner_i.rng);
        static_r.generate(&mut owner_r.rng);
        owner_i.set_s(static_i);
        owner_r.set_s(static_r);

        let mut cipherstate1_i : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_i : CipherState<CipherAESGCM> = Default::default();

        let mut cipherstate1_r : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_r : CipherState<CipherAESGCM> = Default::default();

        let mut h_i = HandshakeState::new_from_owner(&mut owner_i,
                            true,
                            HandshakePattern::XX,
                            &[0u8; 0],
                            None,
                            &mut cipherstate1_i,
                            &mut cipherstate2_i);

        let mut h_r = HandshakeState::new_from_owner(&mut owner_r,
                            false,
                            HandshakePattern::XX,
                            &[0u8; 0],
                            None,
                            &mut cipherstate1_r,
                            &mut cipherstate2_r);
       
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

        assert!(buffer_msg[..64].to_hex() == "8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7");
    } 

    // Noise_IK test
    {        
        let mut static_i:Dh25519 = Default::default();
        let mut static_r:Dh25519 = Default::default();

        let mut owner_i : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA256> = Default::default();
        let mut owner_r : HandshakeCryptoOwner<RandomInc, Dh25519, CipherAESGCM, HashSHA256> = Default::default();

        owner_r.rng.next_byte = 1;
        static_i.generate(&mut owner_i.rng);
        static_r.generate(&mut owner_r.rng);
        owner_i.set_s(static_i);
        owner_i.set_rs(static_r.pubkey());
        owner_r.set_s(static_r);

        let mut cipherstate1_i : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_i : CipherState<CipherAESGCM> = Default::default();

        let mut cipherstate1_r : CipherState<CipherAESGCM> = Default::default();
        let mut cipherstate2_r : CipherState<CipherAESGCM> = Default::default();

        let mut h_i = HandshakeState::new_from_owner(&mut owner_i,
                            true,
                            HandshakePattern::IK,
                            "ABC".as_bytes(),
                            None,
                            &mut cipherstate1_i,
                            &mut cipherstate2_i);

        let mut h_r = HandshakeState::new_from_owner(&mut owner_r,
                            false,
                            HandshakePattern::IK,
                            "ABC".as_bytes(),
                            None,
                            &mut cipherstate1_r,
                            &mut cipherstate2_r);


        let mut buffer_msg = [0u8; 200];
        let mut buffer_out = [0u8; 200];
        assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).0 == 99);
        assert!(h_r.read_message(&buffer_msg[..99], &mut buffer_out).unwrap().0 == 3);
        assert!(buffer_out[..3].to_hex() == "616263");

        assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).0 == 52);
        assert!(h_i.read_message(&buffer_msg[..52], &mut buffer_out).unwrap().0 == 4);
        assert!(buffer_out[..4].to_hex() == "64656667");

        //println!("{}", buffer_msg[..52].to_hex());
        assert!(buffer_msg[..52].to_hex() == "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b7555a94199d0ce2972e0861b06c2152419a278de");
    } 
}
