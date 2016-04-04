
use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;
use symmetricstate::*;
use patterns::*;
use handshakecryptoowner::*;

pub const MAXMSGLEN : usize = 65535;

#[derive(Debug)]
pub enum NoiseError {DecryptError}

pub struct HandshakeState<'a> {
    rng : &'a mut RandomType,                    /* for generating ephemerals */
    symmetricstate : SymmetricState<'a>,         /* for handshaking */
    cipherstate1: &'a mut CipherStateType,       /* for I->R transport msgs */
    cipherstate2: &'a mut CipherStateType,       /* for I<-R transport msgs */ 
    s: &'a DhType,
    e: &'a mut DhType,
    rs: &'a mut [u8],
    re: &'a mut [u8],
    has_s: bool,
    has_e: bool,
    has_rs: bool,
    has_re: bool,
    my_turn_to_send : bool,
    message_patterns : [[Token; 10]; 10],
    message_index: usize,
}

impl<'a> HandshakeState<'a> {

    pub fn new_from_owner<R: RandomType + Default, 
                          D: DhType + Default, 
                          C: CipherType + Default, 
                          H: HashType + Default> 
                         (owner: &'a mut HandshakeCryptoOwner<R, D, C, H>,
                          initiator: bool,
                          handshake_pattern: HandshakePattern,
                          prologue: &[u8],
                          optional_preshared_key: Option<&[u8]>,
                          cipherstate1: &'a mut CipherStateType,
                          cipherstate2: &'a mut CipherStateType) -> HandshakeState<'a> {

        let dhlen = owner.s.pub_len();
        HandshakeState::<'a>::new(
            &mut owner.rng,
            &mut owner.cipherstate,
            &mut owner.hasher,
            &mut owner.s, &mut owner.e, 
            &mut owner.rs[..dhlen], 
            &mut owner.re[..dhlen],
            owner.has_s, owner.has_e, owner.has_rs, owner.has_re,
            initiator, handshake_pattern, prologue, optional_preshared_key,
            cipherstate1, cipherstate2)
    }

    pub fn new(rng: &'a mut RandomType,
               cipherstate: &'a mut CipherStateType,
               hasher: &'a mut HashType,
               s : &'a DhType, 
               e : &'a mut DhType, 
               rs: &'a mut [u8],
               re: &'a mut [u8],
               has_s: bool,
               has_e: bool,
               has_rs: bool,
               has_re: bool,
               initiator: bool,
               handshake_pattern: HandshakePattern,
               prologue: &[u8],
               optional_preshared_key: Option<&[u8]>,
               cipherstate1: &'a mut CipherStateType,
               cipherstate2: &'a mut CipherStateType) -> HandshakeState<'a> {
        let mut handshake_name = [0u8; 128];
        let mut name_len: usize;
        let mut premsg_pattern_i = [Token::Empty; 2];
        let mut premsg_pattern_r = [Token::Empty; 2];
        let mut message_patterns = [[Token::Empty; 10]; 10];

        // Check that trait objects are pointing to consistent types
        // (same cipher, same DH) by looking at names
        {
            let mut test_name1 = [0u8; 32];
            let mut test_name2 = [0u8; 32];

            test_name1 = [0u8; 32];
            test_name2 = [0u8; 32];
            assert!(cipherstate.name(&mut test_name1) < 32);
            cipherstate1.name(&mut test_name2);
            assert!(test_name1 == test_name2);
            cipherstate2.name(&mut test_name2);
            assert!(test_name1 == test_name2);

            test_name1 = [0u8; 32];
            test_name2 = [0u8; 32];
            assert!(s.name(&mut test_name1) < 32);
            e.name(&mut test_name2);
            assert!(test_name1 == test_name2);
        }

        // Check that public keys are the right length 
        {
            assert!(s.pub_len() == e.pub_len());
            assert!(s.pub_len() <= rs.len());
            assert!(s.pub_len() <= re.len());
        }

        if let Some(_) = optional_preshared_key {
            copy_memory("NoisePSK_".as_bytes(), &mut handshake_name);
            name_len = 9;
        } else {
            copy_memory("Noise_".as_bytes(), &mut handshake_name);
            name_len = 6;
        }
        name_len += resolve_handshake_pattern(handshake_pattern,
                                              &mut handshake_name[name_len..],
                                              &mut premsg_pattern_i, 
                                              &mut premsg_pattern_r, 
                                              &mut message_patterns);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += s.name(&mut handshake_name[name_len..]);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += cipherstate.name(&mut handshake_name[name_len..]);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += hasher.name(&mut handshake_name[name_len..]);

        let mut symmetricstate = SymmetricState::new(cipherstate, hasher);
        symmetricstate.initialize(&handshake_name[..name_len]); 
        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = optional_preshared_key { 
            symmetricstate.mix_preshared_key(preshared_key);
        }

        if initiator {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => {assert!(has_rs); symmetricstate.mix_hash(rs);},
                    Token::E => {assert!(has_re); symmetricstate.mix_hash(re);},
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        } else {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => {assert!(has_rs); symmetricstate.mix_hash(rs);},
                    Token::E => {assert!(has_re); symmetricstate.mix_hash(re);},
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        }

        HandshakeState{
            rng: rng,  
            symmetricstate: symmetricstate,
            cipherstate1: cipherstate1,
            cipherstate2: cipherstate2,
            s: s, 
            e: e, 
            rs: rs, 
            re: re, 
            has_s: has_s, 
            has_e: has_e,
            has_rs: has_rs, 
            has_re: has_re,
            my_turn_to_send: initiator,
            message_patterns: message_patterns, 
            message_index: 0, 
            }
    }

    fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) {
        assert!(!local_s || self.has_s);
        assert!(local_s || self.has_e);
        assert!(!remote_s || self.has_rs);
        assert!(remote_s || self.has_re);

        let dh_len = self.dh_len();
        let mut dh_out = [0u8; MAXDHLEN];
        if local_s && remote_s {
            self.s.dh(self.rs, &mut dh_out);
        }
        if local_s && !remote_s {
            self.s.dh(self.re, &mut dh_out);
        }
        if !local_s && remote_s {
            self.e.dh(self.rs, &mut dh_out);
        }
        if !local_s && !remote_s {
            self.e.dh(self.re, &mut dh_out);
        }
        self.symmetricstate.mix_key(&dh_out[..dh_len]);
    }

    pub fn write_message(&mut self, 
                         payload: &[u8], 
                         message: &mut [u8]) -> (usize, bool) { 
        assert!(self.my_turn_to_send);
        let tokens = self.message_patterns[self.message_index];
        let mut last = false;
        if let Token::Empty = self.message_patterns[self.message_index+1][0] {
            last = true;
        }
        self.message_index += 1;

        let mut byte_index = 0;
        for token in &tokens {
            match *token {
                Token::E => {
                    self.e.generate(self.rng); 
                    let pubkey = self.e.pubkey();
                    copy_memory(pubkey, &mut message[byte_index..]);
                    byte_index += self.s.pub_len();
                    self.symmetricstate.mix_hash(&pubkey);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(&pubkey);
                    }
                    self.has_e = true;
                },
                Token::S => {
                    assert!(self.has_s);
                    byte_index += self.symmetricstate.encrypt_and_hash(
                                        &self.s.pubkey(), 
                                        &mut message[byte_index..]);
                },
                Token::Dhee => self.dh(false, false),
                Token::Dhes => self.dh(false, true),
                Token::Dhse => self.dh(true, false),
                Token::Dhss => self.dh(true, true),
                Token::Empty => break
            }
        }
        self.my_turn_to_send = false;
        byte_index += self.symmetricstate.encrypt_and_hash(payload, &mut message[byte_index..]);
        assert!(byte_index <= MAXMSGLEN);
        if last {
            self.symmetricstate.split(self.cipherstate1, self.cipherstate2);
        }
        (byte_index, last)
    }

    pub fn read_message(&mut self, 
                        message: &[u8], 
                        payload: &mut [u8]) -> Result<(usize, bool), NoiseError> { 
        assert!(self.my_turn_to_send == false);
        assert!(message.len() <= MAXMSGLEN);

        let tokens = self.message_patterns[self.message_index];
        let mut last = false;
        if let Token::Empty = self.message_patterns[self.message_index+1][0] {
            last = true;
        }
        self.message_index += 1;

        let dh_len = self.dh_len();
        let mut ptr = message;
        for token in &tokens {
            match *token {
                Token::E => {
                    copy_memory(&ptr[..dh_len], self.re);
                    ptr = &ptr[dh_len..];
                    self.symmetricstate.mix_hash(self.re);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(self.re);
                    }
                    self.has_re = true;
                },
                Token::S => {
                    let data = if self.symmetricstate.has_key() {
                        let temp = &ptr[..dh_len + TAGLEN];
                        ptr = &ptr[dh_len + TAGLEN..];
                        temp
                    } else {
                        let temp = &ptr[..dh_len];
                        ptr = &ptr[dh_len..];
                        temp
                    };
                    if !self.symmetricstate.decrypt_and_hash(data, self.rs) {
                        return Err(NoiseError::DecryptError);
                    }
                    self.has_rs = true;
                },
                Token::Dhee => self.dh(false, false),
                Token::Dhes => self.dh(true, false),
                Token::Dhse => self.dh(false, true),
                Token::Dhss => self.dh(true, true),
                Token::Empty => break
            }
        }
        if !self.symmetricstate.decrypt_and_hash(ptr, payload) {
            return Err(NoiseError::DecryptError);
        }
        self.my_turn_to_send = true;
        if last {
            self.symmetricstate.split(self.cipherstate1, self.cipherstate2);
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok((payload_len, last))
    }

}


