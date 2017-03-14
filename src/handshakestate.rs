extern crate rustc_serialize;
extern crate arrayvec;

use self::arrayvec::{ArrayVec, ArrayString};
use constants::*;
use utils::*;
use types::*;
use cipherstate::*;
use symmetricstate::*;
use params::*;
use std::ops::{Deref, DerefMut};
use NoiseError;
use NoiseError::*;

// TODO: this doesn't belong here
pub struct CipherStates(pub Box<CipherStateType>, pub Box<CipherStateType>);

impl CipherStates {
    pub fn new(sending: Box<CipherStateType>, receiving: Box<CipherStateType>) -> Result<Self, NoiseError> {
        if sending.name() != receiving.name() {
            return Err(InitError("cipherstates don't match"));
        }

        Ok(CipherStates(sending, receiving))
    }
}

// TODO: This code is not so beautiful.
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

/// A state machine encompassing the handshake phase of a Noise session.
///
/// **Note:** you are probably looking for [`NoiseBuilder`](struct.NoiseBuilder.html) to
/// get started.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct HandshakeState {
    rng : Box<Random>,
    symmetricstate : SymmetricState,
    cipherstates: CipherStates,
    s: Toggle<Box<Dh>>,
    e: Toggle<Box<Dh>>,
    fixed_ephemeral: bool,
    rs: Toggle<[u8; MAXDHLEN]>,
    re: Toggle<[u8; MAXDHLEN]>,
    initiator: bool,
    my_turn: bool,
    message_patterns: MessagePatterns,
}

impl HandshakeState {
    pub fn new(
        rng: Box<Random>,
        cipherstate: Box<CipherStateType>,
        hasher: Box<Hash>,
        s : Toggle<Box<Dh>>,
        e : Toggle<Box<Dh>>,
        fixed_ephemeral: bool,
        rs: Toggle<[u8; MAXDHLEN]>,
        re: Toggle<[u8; MAXDHLEN]>,
        initiator: bool,
        handshake_pattern: HandshakePattern,
        prologue: &[u8],
        optional_preshared_key: Option<&[u8]>,
        cipherstates: CipherStates) -> Result<HandshakeState, NoiseError> {

        if (s.is_on() && e.is_on()  && s.pub_len() != e.pub_len())
        || (s.is_on() && rs.is_on() && s.pub_len() >  rs.len())
        || (s.is_on() && re.is_on() && s.pub_len() >  re.len())
        {
            return Err(PrereqError(format!("key lengths aren't right. my pub: {}, their: {}", s.pub_len(), rs.len())));
        }

        let prefix = match optional_preshared_key {
            Some(_) => "NoisePSK_",
            None    => "Noise_"
        };
        let mut handshake_name = ArrayString::<[u8; 128]>::from(prefix).unwrap();
        let tokens = HandshakeTokens::from(handshake_pattern);
        handshake_name.push_str(handshake_pattern.as_str()).unwrap();
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

        let dh_len = s.pub_len();
        if initiator {
            for token in tokens.premsg_pattern_i {
                match *token {
                    Token::S => {assert!(s.is_on()); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(e.is_on()); symmetricstate.mix_hash(e.pubkey());},
                    _ => unreachable!()
                }
            }
            for token in tokens.premsg_pattern_r {
                match *token {
                    Token::S => {assert!(rs.is_on()); symmetricstate.mix_hash(&rs[..dh_len]);},
                    Token::E => {assert!(re.is_on()); symmetricstate.mix_hash(&re[..dh_len]);},
                    _ => unreachable!()
                }
            }
        } else {
            for token in tokens.premsg_pattern_i {
                match *token {
                    Token::S => {assert!(rs.is_on()); symmetricstate.mix_hash(&rs[..dh_len]);},
                    Token::E => {assert!(re.is_on()); symmetricstate.mix_hash(&re[..dh_len]);},
                    _ => unreachable!()
                }
            }
            for token in tokens.premsg_pattern_r {
                match *token {
                    Token::S => {assert!(s.is_on()); symmetricstate.mix_hash(s.pubkey());},
                    Token::E => {assert!(e.is_on()); symmetricstate.mix_hash(e.pubkey());},
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
            fixed_ephemeral: fixed_ephemeral,
            rs: rs, 
            re: re,
            initiator: initiator,
            my_turn: initiator,
            message_patterns: tokens.msg_patterns.into(),
        })
    }

    fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) -> Result<(), NoiseError> {
        if !((!local_s  || self.s.is_on())  &&
             ( local_s  || self.e.is_on())  &&
             (!remote_s || self.rs.is_on()) &&
             ( remote_s || self.re.is_on()))
        {
            Err(NoiseError::StateError("missing key material"))
        } else {
            let dh_len = self.dh_len();
            let mut dh_out = [0u8; MAXDHLEN];
            match (local_s, remote_s) {
                (true,  true ) => self.s.dh(&*self.rs, &mut dh_out),
                (true,  false) => self.s.dh(&*self.re, &mut dh_out),
                (false, true ) => self.e.dh(&*self.rs, &mut dh_out),
                (false, false) => self.e.dh(&*self.re, &mut dh_out),
            }
            self.symmetricstate.mix_key(&dh_out[..dh_len]);
            Ok(())
        }
    }

    pub fn is_write_encrypted(&self) -> bool {
        self.symmetricstate.has_key()
    }

    pub fn write_handshake_message(&mut self,
                         payload: &[u8], 
                         message: &mut [u8]) -> Result<usize, NoiseError> {
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
                    if !self.fixed_ephemeral {
                        self.e.generate(&mut *self.rng);
                    }
                    {
                        let pubkey = self.e.pubkey();
                        copy_memory(pubkey, &mut message[byte_index..]);
                        byte_index += self.s.pub_len();
                        self.symmetricstate.mix_hash(&pubkey);
                        if self.symmetricstate.has_preshared_key() {
                            self.symmetricstate.mix_key(&pubkey);
                        }
                    }
                    self.e.enable();
                },
                Token::S => {
                    if !self.s.is_on() {
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
            self.symmetricstate.split(&mut *self.cipherstates.0, &mut *self.cipherstates.1);
        }
        Ok(byte_index)
    }

    pub fn read_handshake_message(&mut self,
                        message: &[u8], 
                        payload: &mut [u8]) -> Result<usize, NoiseError> {
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
                        self.re[..dh_len].copy_from_slice(&ptr[..dh_len]);
                        ptr = &ptr[dh_len..];
                        self.symmetricstate.mix_hash(&self.re[..dh_len]);
                        if self.symmetricstate.has_preshared_key() {
                            self.symmetricstate.mix_key(&self.re[..dh_len]);
                        }
                        self.re.enable();
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
                        self.symmetricstate.decrypt_and_hash(data, &mut self.rs[..dh_len]).map_err(|_| NoiseError::DecryptError)?;
                        self.rs.enable();
                    },
                    Token::Dhee => self.dh(false, false)?,
                    Token::Dhes => self.dh(true, false)?,
                    Token::Dhse => self.dh(false, true)?,
                    Token::Dhss => self.dh(true, true)?,
                }
            }
        }
        self.symmetricstate.decrypt_and_hash(ptr, payload).map_err(|_| NoiseError::DecryptError)?;
        self.my_turn = true;
        if last {
            self.symmetricstate.split(&mut *self.cipherstates.0, &mut *self.cipherstates.1);
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok(payload_len)
    }

    pub fn finish(self) -> Result<CipherStates, NoiseError> {
        if self.is_finished() {
            Ok(self.cipherstates)
        } else {
            Err(StateError("handshake not yet completed"))
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    pub fn is_finished(&self) -> bool {
        self.message_patterns.is_empty()
    }
}


