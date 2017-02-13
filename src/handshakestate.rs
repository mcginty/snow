extern crate rustc_serialize;
extern crate arrayvec;

use self::arrayvec::{ArrayVec, ArrayString};
use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;
use symmetricstate::*;
use patterns::*;
use std::ops::{Deref, DerefMut};


#[derive(Debug)]
pub enum NoiseError {
    InitError(&'static str),
    PrereqError(String),
    InputError(&'static str),
    StateError(&'static str),
    DecryptError
}

pub struct CipherStates(Box<CipherStateType>, Box<CipherStateType>);

impl CipherStates {
    pub fn new(sending: Box<CipherStateType>, receiving: Box<CipherStateType>) -> Result<Self, NoiseError> {
        if sending.name() != receiving.name() {
            return Err(NoiseError::InitError("cipherstates don't match"));
        }

        Ok(CipherStates(sending, receiving))
    }
}

type MessagePatternInner = ArrayVec<[ArrayVec<[Token; 10]>; 10]>;
struct MessagePatterns(MessagePatternInner);
impl Deref for MessagePatterns {
    type Target = MessagePatternInner;

    fn deref(&self) -> &MessagePatternInner {
        &self.0
    }
}

impl DerefMut for MessagePatterns {
    fn deref_mut(&mut self) -> &mut MessagePatternInner {
        &mut self.0
    }
}

impl From<&'static [&'static [Token]]> for MessagePatterns {
    fn from(arrays: &'static [&'static [Token]]) -> Self {
        let mut patterns = ArrayVec::new();
        for i in arrays {
            let mut inner = ArrayVec::new();
            for j in *i {
                inner.push(*j);
            }
            patterns.push(inner);
        }
        MessagePatterns(patterns)
    }
}

// TODO move has_* bools to just using Option<*>, but verify behavior is the same.
pub struct HandshakeState {
    rng : Box<RandomType>,                // for generating ephemerals
    symmetricstate : SymmetricState,      // for handshaking
    cipherstates: CipherStates,
    s: Box<DhType>,                       // local static
    e: Box<DhType>,                       // local ephemeral
    rs: Vec<u8>,                          // remote static
    re: Vec<u8>,                          // remote ephemeral
    handshake_pattern: HandshakePattern,
    has_s: bool,
    has_e: bool,
    has_rs: bool,
    has_re: bool,
    my_turn: bool,
    message_patterns: MessagePatterns, // 2D Token array
}

impl HandshakeState {
    pub fn new(
            rng: Box<RandomType>,
            cipherstate: Box<CipherStateType>,
            hasher: Box<HashType>,
            s : Box<DhType>,
            e : Box<DhType>,
            rs: Vec<u8>,
            re: Vec<u8>,
            has_s: bool,
            has_e: bool,
            has_rs: bool,
            has_re: bool,
            initiator: bool,
            handshake_pattern: HandshakePattern,
            prologue: &[u8],
            optional_preshared_key: Option<Vec<u8>>,
            cipherstates: CipherStates) -> Result<HandshakeState, NoiseError> {
        use self::NoiseError::*;


        if s.name() != e.name() {
            return Err(InitError("cipherstates don't match"));
        }

        if (has_s && has_e  && s.pub_len() != e.pub_len())
        || (has_s && has_rs && s.pub_len() >  rs.len())
        || (has_s && has_re && s.pub_len() >  re.len())
        {
            return Err(PrereqError(format!("key lengths aren't right. my pub: {}, their: {}", s.pub_len(), rs.len())));
        }

        let prefix = match optional_preshared_key {
            Some(_) => "NoisePSK_",
            None    => "Noise_"
        };
        let mut handshake_name = ArrayString::<[u8; 128]>::from(prefix).unwrap();
        let tokens = resolve_handshake_pattern(handshake_pattern);
        handshake_name.push_str(&tokens.name).unwrap();
        handshake_name.push('_').unwrap();
        handshake_name.push_str(s.name()).unwrap();
        handshake_name.push('_').unwrap();
        handshake_name.push_str(cipherstate.name()).unwrap();
        handshake_name.push('_').unwrap();
        handshake_name.push_str(hasher.name()).unwrap();

        let mut symmetricstate = SymmetricState::new(cipherstate, hasher);

        symmetricstate.initialize(&handshake_name[..]);
        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = optional_preshared_key { 
            symmetricstate.mix_preshared_key(&preshared_key);
        }

        if initiator {
            for token in tokens.premsg_pattern_i {
                match *token {
                    Token::S => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    _ => unreachable!()
                }
            }
            for token in tokens.premsg_pattern_r {
                match *token {
                    Token::S => {assert!(has_rs); symmetricstate.mix_hash(&rs);},
                    Token::E => {assert!(has_re); symmetricstate.mix_hash(&re);},
                    _ => unreachable!()
                }
            }
        } else {
            for token in tokens.premsg_pattern_i {
                match *token {
                    Token::S => {assert!(has_rs); symmetricstate.mix_hash(&rs);},
                    Token::E => {assert!(has_re); symmetricstate.mix_hash(&re);},
                    _ => unreachable!()
                }
            }
            for token in tokens.premsg_pattern_r {
                match *token {
                    Token::S => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    _ => unreachable!()
                }
            }
        }

        Ok(HandshakeState {
            rng: rng,  
            symmetricstate: symmetricstate,
            cipherstates: cipherstates,
            s: s,
            e: e, 
            rs: rs, 
            re: re,
            has_s: has_s,
            has_e: has_e,
            has_rs: has_rs,
            has_re: has_re,
            handshake_pattern: handshake_pattern,
            my_turn: initiator,
            message_patterns: tokens.msg_patterns.into(),
        })
    }

    fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) -> Result<(), NoiseError> {
        if !((!local_s  || self.has_s)  &&
             ( local_s  || self.has_e)  &&
             (!remote_s || self.has_rs) &&
             ( remote_s || self.has_re))
        {
            Err(NoiseError::StateError("missing key material"))
        } else {
            let dh_len = self.dh_len();
            let mut dh_out = [0u8; MAXDHLEN];
            match (local_s, remote_s) {
                (true,  true ) => self.s.dh(&self.rs, &mut dh_out),
                (true,  false) => self.s.dh(&self.re, &mut dh_out),
                (false, true ) => self.e.dh(&self.rs, &mut dh_out),
                (false, false) => self.e.dh(&self.re, &mut dh_out),
            }
            self.symmetricstate.mix_key(&dh_out[..dh_len]);
            Ok(())
        }
    }

    pub fn write_message(&mut self, 
                         payload: &[u8], 
                         message: &mut [u8]) -> Result<(usize, bool), NoiseError> {
        if !self.my_turn {
            return Err(NoiseError::StateError("not ready to write messages yet."));
        }

        let next_tokens = if !self.message_patterns.is_empty() {
            self.message_patterns.remove(0).unwrap()
        } else {
            return Err(NoiseError::StateError("no more message patterns"));
        };
        let last = self.message_patterns.is_empty();

        let mut byte_index = 0;
        for token in next_tokens.iter() {
            match *token {
                Token::E => {
                    self.e.generate(self.rng.deref_mut());
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
                    if !self.has_s {
                        return Err(NoiseError::StateError("self.has_s is false"));
                    }
                    byte_index += self.symmetricstate.encrypt_and_hash(
                        &self.s.pubkey(),
                        &mut message[byte_index..]);
                },
                Token::Dhee => self.dh(false, false)?,
                Token::Dhes => self.dh(false, true )?,
                Token::Dhse => self.dh(true,  false)?,
                Token::Dhss => self.dh(true,  true )?,
            }
        }

        self.my_turn = false;
        byte_index += self.symmetricstate.encrypt_and_hash(payload, &mut message[byte_index..]);
        if byte_index > MAXMSGLEN {
            return Err(NoiseError::InputError("with tokens, message size exceeds maximum"));
        }
        if last {
            self.symmetricstate.split(self.cipherstates.0.deref_mut(), self.cipherstates.1.deref_mut());
        }
        Ok((byte_index, last))
    }

    pub fn read_message(&mut self, 
                        message: &[u8], 
                        payload: &mut [u8]) -> Result<(usize, bool), NoiseError> {
        if message.len() > MAXMSGLEN {
            return Err(NoiseError::InputError("msg greater than max message length"));
        }

        let next_tokens = if self.message_patterns.len() > 0 {
            self.message_patterns.remove(0)
        } else {
            None
        };
        let last = next_tokens.is_some() && self.message_patterns.is_empty();

        let dh_len = self.dh_len();
        let mut ptr = message;
        if let Some(tokens) = next_tokens {
            for token in tokens.iter() {
                match *token {
                    Token::E => {
                        self.re.clear();
                        self.re.extend_from_slice(&ptr[..dh_len]);
                        ptr = &ptr[dh_len..];
                        self.symmetricstate.mix_hash(&self.re);
                        if self.symmetricstate.has_preshared_key() {
                            self.symmetricstate.mix_key(&self.re);
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
                        self.rs.clear();
                        self.rs.resize(32, 0); // XXX
                        if !self.symmetricstate.decrypt_and_hash(data, &mut self.rs[..]) {
                            return Err(NoiseError::DecryptError);
                        }
                        self.has_rs = true;
                    },
                    Token::Dhee => self.dh(false, false)?,
                    Token::Dhes => self.dh(true, false)?,
                    Token::Dhse => self.dh(false, true)?,
                    Token::Dhss => self.dh(true, true)?,
                }
            }
        }
        if !self.symmetricstate.decrypt_and_hash(ptr, payload) {
            return Err(NoiseError::DecryptError);
        }
        self.my_turn = true;
        if last {
            self.symmetricstate.split(self.cipherstates.0.deref_mut(), self.cipherstates.1.deref_mut());
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok((payload_len, last))
    }

    pub fn finish(self) -> CipherStates {
        self.cipherstates
    }

}


