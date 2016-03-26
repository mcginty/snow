
use crypto_stuff::*;
use patterns::*;

pub const MAXMSGLEN : usize = 65535;

#[derive(Debug)]
pub enum NoiseError {DecryptError}

pub trait SymmetricStateType {
    fn cipher_name(&self, out : &mut [u8]) -> usize;
    fn hash_name(&self, out : &mut [u8]) -> usize;
    fn initialize(&mut self, handshake_name: &[u8]);
    fn mix_key(&mut self, data: &[u8]);
    fn mix_hash(&mut self, data: &[u8]);
    fn mix_preshared_key(&mut self, psk: &[u8]);
    fn has_key(&self) -> bool;
    fn has_preshared_key(&self) -> bool;
    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize;
    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool;
    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType);
}

pub struct SymmetricState<'a> {
    cipherstate : &'a mut CipherStateType,
    h : [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    ck: [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    hasher: &'a mut HashType,
    has_key: bool,
    has_preshared_key: bool,
}

pub struct HandshakeState<'a> {
    symmetricstate : &'a mut SymmetricStateType,
    cipherstate1: &'a mut CipherStateType,
    cipherstate2: &'a mut CipherStateType,
    s: &'a DhType,
    e: &'a mut DhType,
    rs: Option<[u8; DHLEN]>,
    re: Option<[u8; DHLEN]>,
    my_turn_to_send : bool,
    message_patterns : [[Token; 10]; 10],
    message_index: usize,
    rng : &'a mut RandomType,
}

impl<'a> SymmetricState<'a> {

    fn new(cipherstate: &'a mut CipherStateType, hasher: &'a mut HashType) -> SymmetricState<'a> {
        SymmetricState{
            cipherstate: cipherstate,
            h: [0u8; MAXHASHLEN],
            ck : [0u8; MAXHASHLEN],
            hasher: hasher,
            has_key: false,
            has_preshared_key: false,
        }
    }
}

impl<'a> SymmetricStateType for SymmetricState<'a> {

    fn cipher_name(&self, out : &mut [u8]) -> usize {
        self.cipherstate.name(out)
    }

    fn hash_name(&self, out : &mut [u8]) -> usize {
        self.hasher.name(out)
    }

    fn initialize(&mut self, handshake_name: &[u8]) {
        if handshake_name.len() <= self.hasher.hash_len() {
            self.h = [0u8; MAXHASHLEN];
            copy_memory(handshake_name, &mut self.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name); 
            self.hasher.result(&mut self.h);
        }
        copy_memory(&self.h, &mut self.ck);
        self.cipherstate.clear();
        self.has_key = false;
        self.has_preshared_key = false;
    }

    fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.cipherstate.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.h);
    }

    fn mix_preshared_key(&mut self, psk: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.has_preshared_key = true;
    }

    fn has_key(&self) -> bool {
       self.has_key
    }

    fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let hash_len = self.hasher.hash_len();
        let output_len:usize;
        if !self.cipherstate.is_empty() {
            self.cipherstate.encrypt_ad(&self.h[..hash_len], plaintext, out);
            output_len = plaintext.len() + TAGLEN;
        }
        else {
            copy_memory(plaintext, out);
            output_len = plaintext.len();
        }
        self.mix_hash(&out[..output_len]);
        output_len
    }

    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        let hash_len = self.hasher.hash_len();
        if !self.cipherstate.is_empty() {
            if !self.cipherstate.decrypt_ad(&self.h[..hash_len], data, out) { 
                return false; 
            }
        }
        else {
            copy_memory(data, out);
        }
        self.mix_hash(data);
        true
    }

    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType) {
        assert!(!self.cipherstate.is_empty());
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], &[0u8; 0], 
                         &mut hkdf_output.0, 
                         &mut hkdf_output.1);
        child1.set(&hkdf_output.0[..CIPHERKEYLEN], 0);
        child2.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
    }

}

impl<'a> HandshakeState<'a> {

    pub fn new(rng: &'a mut RandomType,
               symmetricstate: &'a mut SymmetricStateType,
               cipherstate1: &'a mut CipherStateType,
               cipherstate2: &'a mut CipherStateType,
               handshake_pattern: HandshakePattern,
               initiator: bool,
               prologue: &[u8],
               optional_preshared_key: Option<&[u8]>,
               s : &'a DhType, 
               e : &'a mut DhType, 
               rs: Option<[u8; DHLEN]>, 
               re: Option<[u8; DHLEN]>) -> HandshakeState<'a> {
        let mut handshake_name = [0u8; 128];
        let mut name_len: usize;
        let mut premsg_pattern_i = [Token::Empty; 2];
        let mut premsg_pattern_r = [Token::Empty; 2];
        let mut message_patterns = [[Token::Empty; 10]; 10];

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
        name_len += symmetricstate.hash_name(&mut handshake_name[name_len..]);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += symmetricstate.cipher_name(&mut handshake_name[name_len..]);

        symmetricstate.initialize(&handshake_name[..name_len]); 
        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = optional_preshared_key { 
            symmetricstate.mix_preshared_key(preshared_key);
        }

        if initiator {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => symmetricstate.mix_hash(s.pubkey()),
                    Token::E => symmetricstate.mix_hash(e.pubkey()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => symmetricstate.mix_hash(&rs.unwrap()),
                    Token::E => symmetricstate.mix_hash(&re.unwrap()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        } else {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => symmetricstate.mix_hash(&rs.unwrap()),
                    Token::E => symmetricstate.mix_hash(&re.unwrap()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => symmetricstate.mix_hash(s.pubkey()),
                    Token::E => symmetricstate.mix_hash(e.pubkey()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        }

        HandshakeState{
            symmetricstate: symmetricstate, 
            cipherstate1: cipherstate1,
            cipherstate2: cipherstate2,
            s: s, e: e, rs: rs, re: re, 
            my_turn_to_send: initiator,
            message_patterns: message_patterns, 
            message_index: 0, 
            rng: rng,  
            }
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
                    byte_index += DHLEN;
                    self.symmetricstate.mix_hash(&pubkey);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(&pubkey);
                    }
                },
                Token::S => {
                    byte_index += self.symmetricstate.encrypt_and_hash(
                                        &self.s.pubkey(), 
                                        &mut message[byte_index..]);
                },
                Token::Dhee => self.symmetricstate.mix_key(&self.e.dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.e.dh(&self.rs.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.s.dh(&self.re.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.dh(&self.rs.unwrap())),
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

        let mut ptr = message;
        for token in &tokens {
            match *token {
                Token::E => {
                    let mut pubkey = [0u8; DHLEN];
                    copy_memory(&ptr[..DHLEN], &mut pubkey);
                    ptr = &ptr[DHLEN..];
                    self.re = Some(pubkey);
                    self.symmetricstate.mix_hash(&pubkey);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(&pubkey);
                    }
                },
                Token::S => {
                    let data = if self.symmetricstate.has_key() {
                        let temp = &ptr[..DHLEN + TAGLEN]; 
                        ptr = &ptr[DHLEN + TAGLEN..]; 
                        temp
                    } else {
                        let temp = &ptr[..DHLEN];        
                        ptr = &ptr[DHLEN..];        
                        temp
                    };
                    let mut pubkey = [0u8; DHLEN];
                    if !self.symmetricstate.decrypt_and_hash(data, &mut pubkey) {
                        return Err(NoiseError::DecryptError);
                    }
                    self.rs = Some(pubkey);
                },
                Token::Dhee => self.symmetricstate.mix_key(&self.e.dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.s.dh(&self.re.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.e.dh(&self.rs.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.dh(&self.rs.unwrap())),
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


