
use std::marker::PhantomData;
use crypto_stuff::*;

pub enum Token {E, S, Dhee, Dhes, Dhse, Dhss}

#[derive(Debug)]
pub enum NoiseError {DecryptError}

struct SymmetricState<C: Cipher, H: Hash> {
    cipherstate : C,
    has_key : bool,
    h : [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    ck: [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    wtf : PhantomData<H>, /* So rust thinks I'm using H, this is ugly */
}

pub struct HandshakeState<D: Dh, C: Cipher, H: Hash> {
    symmetricstate: SymmetricState<C, H>,
    s: Option<D>,
    e: Option<D>,
    rs: Option<[u8; DHLEN]>,
    re: Option<[u8; DHLEN]>,
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
            cipherstate: C::new(&[0u8; CIPHERKEYLEN], 0), 
            has_key : false, 
            h: hname,
            ck : hname, 
            wtf: PhantomData::<H>
        }
    }

    fn mix_key(&mut self, data: &[u8]) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        H::hkdf(&self.ck[..H::hash_len()], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.cipherstate = C::new(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = H::new();
        hasher.input(&self.h[..H::hash_len()]);
        hasher.input(data);
        hasher.result(&mut self.h);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        if self.has_key {
            self.cipherstate.encrypt_and_inc(&self.h[..H::hash_len()], plaintext, out);
            self.mix_hash(&out[..plaintext.len() + TAGLEN]);
            return plaintext.len() + TAGLEN;
        } else {
            copy_memory(plaintext, out);
            self.mix_hash(plaintext);
            return plaintext.len();
        }
    }

    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        if self.has_key {
            if !self.cipherstate.decrypt_and_inc(&self.h[..H::hash_len()], data, out) { 
                return false; 
            }
        }
        else {
            copy_memory(data, out)
        }
        self.mix_hash(data);
        true
    }

    fn split(&self) -> (C, C) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        H::hkdf(&self.ck[..H::hash_len()], &[0u8; 0], &mut hkdf_output.0, &mut hkdf_output.1);
        let c1 = C::new(&hkdf_output.0[..CIPHERKEYLEN], 0);
        let c2 = C::new(&hkdf_output.1[..CIPHERKEYLEN], 0);
        (c1, c2)
    }

}

impl <D: Dh, C: Cipher, H: Hash> HandshakeState<D, C, H> {

    pub fn new(handshake_name: &[u8], 
               new_s : Option<D>, 
               new_e : Option<D>, 
               new_rs: Option<[u8; DHLEN]>, 
               new_re: Option<[u8; DHLEN]> ) -> HandshakeState<D, C, H> {
        let symmetricstate = SymmetricState::new(handshake_name); 
        HandshakeState{symmetricstate: symmetricstate, s: new_s, e: new_e, rs: new_rs, re: new_re}
    }

    pub fn write_message(&mut self, 
                         descriptor: &[Token], 
                         last: bool, 
                         payload: &[u8], 
                         out: &mut [u8]) -> (usize, Option<(C, C)>) { 
        let mut index = 0;
        for token in descriptor {
            match *token {
                Token::E => {
                    self.e = Some(D::generate()); 
                    index += self.symmetricstate.encrypt_and_hash(&self.e.as_ref().unwrap().pubkey(), &mut out[index..]); 
                },
                Token::S => index += self.symmetricstate.encrypt_and_hash(&self.s.as_ref().unwrap().pubkey(), &mut out[index..]),
                Token::Dhee => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.rs.unwrap())),
            }
        }
        index += self.symmetricstate.encrypt_and_hash(payload, &mut out[index..]);
        match last {
            true => (index, Some(self.symmetricstate.split())),
            false => (index, None)
        }
    }

    pub fn read_message(&mut self, 
                        descriptor: &[Token], 
                        last: bool, 
                        buffer: &[u8], 
                        out: &mut [u8]) -> Result<(usize, Option<(C, C)>), NoiseError> { 
        let mut ptr = buffer;
        for token in descriptor {
            match *token {
                Token::E | Token::S => {
                    let data = match self.symmetricstate.has_key {
                        true =>  {
                            let temp = &ptr[..DHLEN + TAGLEN]; 
                            ptr = &ptr[DHLEN + TAGLEN..]; 
                            temp
                        }
                        false => {
                            let temp = &ptr[..DHLEN];        
                            ptr = &ptr[DHLEN..];        
                            temp
                        }
                    };
                    let mut pubkey = [0u8; DHLEN];
                    if !self.symmetricstate.decrypt_and_hash(data, &mut pubkey) {
                        return Err(NoiseError::DecryptError);
                    }
                    match *token {
                        Token::E => self.re = Some(pubkey),
                        Token::S => self.rs = Some(pubkey),
                        _ => unreachable!(),
                    }
                },
                Token::Dhee => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhes => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.re.unwrap())),
                Token::Dhse => self.symmetricstate.mix_key(&self.e.as_ref().unwrap().dh(&self.rs.unwrap())),
                Token::Dhss => self.symmetricstate.mix_key(&self.s.as_ref().unwrap().dh(&self.rs.unwrap())),
            }
        }
        let mut payload_len : usize = 0;
        if self.symmetricstate.has_key { 
            payload_len = ptr.len() - TAGLEN; 
        } else { 
            payload_len = ptr.len(); 
        }
        if !self.symmetricstate.decrypt_and_hash(ptr, out) {
            return Err(NoiseError::DecryptError);
        }
        match last {
            true => Ok( (payload_len, Some(self.symmetricstate.split()) ) ),
            false => Ok( (payload_len, None) ) 
        }
    }

}


