
use std::marker::PhantomData;
use crypto_stuff::*;
use patterns::*;

pub const MAXMSGLEN : usize = 65535;

#[derive(Debug)]
pub enum NoiseError {DecryptError}

struct SymmetricState<C: Cipher, H: Hash> {
    cipherstate : Option< CipherState<C> >,
    h : [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    ck: [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    has_psk: bool,
    wtf : PhantomData<H>, /* So rust thinks I'm using H, this is ugly */
}

pub struct HandshakeState<'a, D: Dh, C: Cipher, H: Hash> {
    symmetricstate: SymmetricState<C, H>,
    s: Option<D>,
    e: Option<D>,
    rs: Option<[u8; DHLEN]>,
    re: Option<[u8; DHLEN]>,
    my_turn_to_send : bool,
    message_patterns : [[Token; 10]; 10],
    message_index: usize,
    initiator: bool,
    rng : &'a mut Random,
}


impl <C: Cipher, H: Hash> SymmetricState<C, H> {

    fn new(handshake_name: &[u8]) -> SymmetricState<C, H> {
        let mut hname = [0u8; MAXHASHLEN];
        if handshake_name.len() <= H::hash_len() {
            copy_memory(handshake_name, &mut hname);
        } else {
            let mut hasher = H::new(); 
            hasher.input(handshake_name); 
            hasher.result(&mut hname);
        }
        SymmetricState{
            cipherstate: None,
            h: hname,
            ck : hname, 
            has_psk: false,
            wtf: PhantomData::<H>
        }
    }

    fn mix_key(&mut self, data: &[u8]) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        H::hkdf(&self.ck[..H::hash_len()], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.cipherstate = Some(CipherState::new(&hkdf_output.1[..CIPHERKEYLEN], 0));
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = H::new();
        hasher.input(&self.h[..H::hash_len()]);
        hasher.input(data);
        hasher.result(&mut self.h);
    }

    fn mix_preshared_key(&mut self, psk: &[u8]) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        H::hkdf(&self.ck[..H::hash_len()], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.mix_hash(&hkdf_output.1[..H::hash_len()]);
        self.has_psk = true;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let output_len:usize;
        if let Some(ref mut cipherstate) = self.cipherstate {
            cipherstate.encrypt_ad(&self.h[..H::hash_len()], plaintext, out);
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
        if let Some(ref mut cipherstate) = self.cipherstate {
            if !cipherstate.decrypt_ad(&self.h[..H::hash_len()], data, out) { 
                return false; 
            }
        }
        else {
            copy_memory(data, out);
        }
        self.mix_hash(data);
        true
    }

    fn split(&self, initiator: bool) -> (CipherState<C>, CipherState<C>) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        H::hkdf(&self.ck[..H::hash_len()], &[0u8; 0], &mut hkdf_output.0, &mut hkdf_output.1);
        let c1 = CipherState::<C>::new(&hkdf_output.0[..CIPHERKEYLEN], 0);
        let c2 = CipherState::<C>::new(&hkdf_output.1[..CIPHERKEYLEN], 0);
        if initiator { (c1, c2) } else { (c2, c1) }
    }

}

impl <'a, D: Dh, C: Cipher, H: Hash> HandshakeState<'a, D, C, H> {

    pub fn new(rng: &'a mut Random,
               handshake_pattern: HandshakePattern,
               initiator: bool,
               prologue: &[u8],
               new_preshared_key: Option<&[u8]>,
               new_s : Option<D>, 
               new_e : Option<D>, 
               new_rs: Option<[u8; DHLEN]>, 
               new_re: Option<[u8; DHLEN]>) -> HandshakeState<'a, D, C, H> {
        let mut handshake_name = [0u8; 128];
        let mut name_len: usize;
        let mut premsg_pattern_i = [Token::Empty; 2];
        let mut premsg_pattern_r = [Token::Empty; 2];
        let mut message_patterns = [[Token::Empty; 10]; 10];

        if let Some(_) = new_preshared_key {
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
        name_len += D::name(&mut handshake_name[name_len..]);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += C::name(&mut handshake_name[name_len..]);
        handshake_name[name_len] = '_' as u8;
        name_len += 1;
        name_len += H::name(&mut handshake_name[name_len..]);

        let mut symmetricstate = SymmetricState::new(&handshake_name[..name_len]); 

        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = new_preshared_key { 
            symmetricstate.mix_preshared_key(preshared_key);
        }

        if initiator {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => symmetricstate.mix_hash(new_s.as_ref().unwrap().pubkey()),
                    Token::E => symmetricstate.mix_hash(new_e.as_ref().unwrap().pubkey()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => symmetricstate.mix_hash(&new_rs.unwrap()),
                    Token::E => symmetricstate.mix_hash(&new_re.unwrap()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        } else {
            for token in &premsg_pattern_i {
                match *token {
                    Token::S => symmetricstate.mix_hash(&new_rs.unwrap()),
                    Token::E => symmetricstate.mix_hash(&new_re.unwrap()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
            for token in &premsg_pattern_r {
                match *token {
                    Token::S => symmetricstate.mix_hash(new_s.as_ref().unwrap().pubkey()),
                    Token::E => symmetricstate.mix_hash(new_e.as_ref().unwrap().pubkey()),
                    Token::Empty => break,
                    _ => unreachable!()
                }
            }
        }

        HandshakeState{
            symmetricstate: symmetricstate, 
            s: new_s, e: new_e, rs: new_rs, re: new_re, 
            my_turn_to_send: initiator,
            message_patterns: message_patterns, 
            message_index: 0, 
            initiator: initiator, 
            rng: rng,  
            }
    }

    pub fn write_message(&mut self, 
                         payload: &[u8], 
                         message: &mut [u8]) -> (usize, Option<(CipherState<C>, CipherState<C>)>) { 
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
                    self.e = Some(D::generate(self.rng)); 
                    let pubkey = self.e.as_ref().unwrap().pubkey();
                    copy_memory(pubkey, &mut message[byte_index..]);
                    byte_index += DHLEN;
                    self.symmetricstate.mix_hash(&pubkey);
                    if self.symmetricstate.has_psk {
                        self.symmetricstate.mix_key(&pubkey);
                    }
                },
                Token::S => {
                    byte_index += self.symmetricstate.encrypt_and_hash(
                                        &self.s.as_ref().unwrap().pubkey(), 
                                        &mut message[byte_index..]);
                },
                Token::Dhee => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Empty => break
            }
        }
        self.my_turn_to_send = false;
        byte_index += self.symmetricstate.encrypt_and_hash(payload, &mut message[byte_index..]);
        assert!(byte_index <= MAXMSGLEN);
        match last {
            true => (byte_index, Some(self.symmetricstate.split(self.initiator))),
            false => (byte_index, None)
        }
    }

    pub fn read_message(&mut self, 
                        message: &[u8], 
                        payload: &mut [u8]) -> 
                            Result<(usize, Option<(CipherState<C>, CipherState<C>)>), 
                                    NoiseError> { 
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
                    if self.symmetricstate.has_psk {
                        self.symmetricstate.mix_key(&pubkey);
                    }
                },
                Token::S => {
                    let data = match self.symmetricstate.cipherstate {
                        Some(_) =>  {
                            let temp = &ptr[..DHLEN + TAGLEN]; 
                            ptr = &ptr[DHLEN + TAGLEN..]; 
                            temp
                        }
                        None => {
                            let temp = &ptr[..DHLEN];        
                            ptr = &ptr[DHLEN..];        
                            temp
                        }
                    };
                    let mut pubkey = [0u8; DHLEN];
                    if !self.symmetricstate.decrypt_and_hash(data, &mut pubkey) {
                        return Err(NoiseError::DecryptError);
                    }
                    self.rs = Some(pubkey);
                },
                Token::Dhee => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Empty => break
            }
        }
        let payload_len = match self.symmetricstate.cipherstate { 
            Some(_) => ptr.len() - TAGLEN,
            None => ptr.len() 
        };
        if !self.symmetricstate.decrypt_and_hash(ptr, payload) {
            return Err(NoiseError::DecryptError);
        }
        self.my_turn_to_send = true;
        match last {
            true => Ok( (payload_len, Some(self.symmetricstate.split(self.initiator)) ) ),
            false => Ok( (payload_len, None) ) 
        }
    }

}


