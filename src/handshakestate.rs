use constants::*;
use utils::*;
use types::*;
use cipherstate::*;
#[cfg(feature = "nightly")] use std::convert::TryFrom;
#[cfg(not(feature = "nightly"))] use utils::TryFrom;
use symmetricstate::*;
use params::*;
use error::{ErrorKind, Result, InitStage, StateProblem};


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
    params: NoiseParams,
    psks: [Option<[u8; PSKLEN]>; 10],
    my_turn: bool,
    message_patterns: MessagePatterns,
}

impl HandshakeState {
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn new(
        rng: Box<Random>,
        cipherstate: CipherState,
        hasher: Box<Hash>,
        s : Toggle<Box<Dh>>,
        e : Toggle<Box<Dh>>,
        fixed_ephemeral: bool,
        rs: Toggle<[u8; MAXDHLEN]>,
        re: Toggle<[u8; MAXDHLEN]>,
        initiator: bool,
        params: NoiseParams,
        psks: [Option<[u8; PSKLEN]>; 10],
        prologue: &[u8],
        cipherstates: CipherStates) -> Result<HandshakeState> {

        if (s.is_on() && e.is_on()  && s.pub_len() != e.pub_len())
        || (s.is_on() && rs.is_on() && s.pub_len() >  rs.len())
        || (s.is_on() && re.is_on() && s.pub_len() >  re.len())
        {
            bail!(ErrorKind::Init(InitStage::ValidateKeyLengths));
        }

        let tokens = HandshakeTokens::try_from(params.handshake.clone())?;

        let mut symmetricstate = SymmetricState::new(cipherstate, hasher);

        symmetricstate.initialize(&params.name);
        symmetricstate.mix_hash(prologue);

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
            params: params,
            psks: psks,
            my_turn: initiator,
            message_patterns: tokens.msg_patterns.into(),
        })
    }

    fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) -> Result<()> {
        if !((!local_s  || self.s.is_on())  &&
             ( local_s  || self.e.is_on())  &&
             (!remote_s || self.rs.is_on()) &&
             ( remote_s || self.re.is_on()))
        {
            bail!(ErrorKind::State(StateProblem::MissingKeyMaterial));
        }
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

    pub fn is_write_encrypted(&self) -> bool {
        self.symmetricstate.has_key()
    }

    pub fn write_handshake_message(&mut self,
                         payload: &[u8], 
                         message: &mut [u8]) -> Result<usize> {
        if !self.my_turn {
            bail!(ErrorKind::State(StateProblem::NotTurnToWrite));
        }

        let next_tokens = if !self.message_patterns.is_empty() {
            self.message_patterns.remove(0).unwrap()
        } else {
            bail!(ErrorKind::State(StateProblem::HandshakeAlreadyFinished));
        };
        let last = self.message_patterns.is_empty();

        let mut byte_index = 0;
        for token in next_tokens.iter() {
            match *token {
                Token::E => {
                    if byte_index + self.e.pub_len() > message.len() {
                        bail!(ErrorKind::Input)
                    }
                    if !self.fixed_ephemeral {
                        self.e.generate(&mut *self.rng);
                    }
                    {
                        let pubkey = self.e.pubkey();
                        copy_memory(pubkey, &mut message[byte_index..]);
                        byte_index += self.s.pub_len();
                        self.symmetricstate.mix_hash(pubkey);
                        if self.params.handshake.is_psk() {
                            self.symmetricstate.mix_key(pubkey);
                        }
                    }
                    self.e.enable();
                },
                Token::S => {
                    if !self.s.is_on() {
                        bail!(ErrorKind::State(StateProblem::MissingKeyMaterial));
                    }
                    if byte_index + self.s.pub_len() > message.len() {
                        bail!(ErrorKind::Input)
                    }
                    byte_index += self.symmetricstate.encrypt_and_mix_hash(
                        self.s.pubkey(),
                        &mut message[byte_index..]);
                },
                Token::Psk(n) => {
                    match self.psks[n as usize] {
                        Some(psk) => {
                            self.symmetricstate.mix_key_and_hash(&psk);
                        },
                        None => {
                            bail!(ErrorKind::State(StateProblem::MissingPsk));
                        }
                    }
                },
                Token::Dhee => self.dh(false, false)?,
                Token::Dhes => self.dh(false, true )?,
                Token::Dhse => self.dh(true,  false)?,
                Token::Dhss => self.dh(true,  true )?,
            }
        }

        self.my_turn = false;
        if byte_index + payload.len() + TAGLEN > message.len() {
            bail!(ErrorKind::Input);
        }
        byte_index += self.symmetricstate.encrypt_and_mix_hash(payload, &mut message[byte_index..]);
        if byte_index > MAXMSGLEN {
            bail!(ErrorKind::Input);
        }
        if last {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        Ok(byte_index)
    }

    pub fn read_handshake_message(&mut self,
                        message: &[u8], 
                        payload: &mut [u8]) -> Result<usize> {
        if message.len() > MAXMSGLEN {
            bail!(ErrorKind::Input);
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
                        if self.params.handshake.is_psk() {
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
                        self.symmetricstate.decrypt_and_mix_hash(data, &mut self.rs[..dh_len]).map_err(|_| ErrorKind::Decrypt)?;
                        self.rs.enable();
                    },
                    Token::Psk(n) => {
                        match self.psks[n as usize] {
                            Some(psk) => {
                                self.symmetricstate.mix_key_and_hash(&psk);
                            },
                            None => {
                                bail!(ErrorKind::State(StateProblem::MissingPsk));
                            }
                        }
                    },
                    Token::Dhee => self.dh(false, false)?,
                    Token::Dhes => self.dh(true, false)?,
                    Token::Dhse => self.dh(false, true)?,
                    Token::Dhss => self.dh(true, true)?,
                }
            }
        }
        self.symmetricstate.decrypt_and_mix_hash(ptr, payload).map_err(|_| ErrorKind::Decrypt)?;
        self.my_turn = true;
        if last {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok(payload_len)
    }

    pub fn get_remote_static(&self) -> Option<&[u8; MAXDHLEN]> {
        self.rs.as_option_ref()
    }

    pub fn finish(self) -> Result<(CipherStates, HandshakeChoice, Toggle<[u8; MAXDHLEN]>)> {
        if self.is_finished() {
            Ok((self.cipherstates, self.params.handshake, self.rs))
        } else {
            bail!(ErrorKind::State(StateProblem::HandshakeNotFinished));
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    pub fn is_finished(&self) -> bool {
        self.message_patterns.is_empty()
    }
}


