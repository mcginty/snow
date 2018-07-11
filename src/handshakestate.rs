use constants::{PSKLEN, TAGLEN, MAXMSGLEN, MAXDHLEN};
use utils::Toggle;
use types::{Dh, Hash, Random};
use cipherstate::{CipherState, CipherStates};
#[cfg(feature = "nightly")] use std::convert::TryFrom;
#[cfg(not(feature = "nightly"))] use utils::TryFrom;
use symmetricstate::SymmetricState;
use params::{HandshakeChoice, HandshakeTokens, MessagePatterns, NoiseParams, Token};
use error::{SnowError, InitStage, StateProblem};


/// A state machine encompassing the handshake phase of a Noise session.
///
/// **Note:** you are probably looking for [`NoiseBuilder`](struct.NoiseBuilder.html) to
/// get started.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct HandshakeState {
    pub(crate) rng              : Box<Random + Send>,
    pub(crate) symmetricstate   : SymmetricState,
    pub(crate) cipherstates     : CipherStates,
    pub(crate) s                : Toggle<Box<Dh + Send>>,
    pub(crate) e                : Toggle<Box<Dh + Send>>,
    pub(crate) fixed_ephemeral  : bool,
    pub(crate) rs               : Toggle<[u8; MAXDHLEN]>,
    pub(crate) re               : Toggle<[u8; MAXDHLEN]>,
    pub(crate) initiator        : bool,
    pub(crate) params           : NoiseParams,
    pub(crate) psks             : [Option<[u8; PSKLEN]>; 10],
    pub(crate) my_turn          : bool,
    pub(crate) message_patterns : MessagePatterns,
    pub(crate) pattern_position : usize,
}

impl HandshakeState {
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn new<'a>(
        rng             : Box<Random + Send>,
        cipherstate     : CipherState,
        hasher          : Box<Hash + Send>,
        s               : Toggle<Box<Dh + Send>>,
        e               : Toggle<Box<Dh + Send>>,
        fixed_ephemeral : bool,
        rs              : Toggle<[u8; MAXDHLEN]>,
        re              : Toggle<[u8; MAXDHLEN]>,
        initiator       : bool,
        params          : NoiseParams,
        psks            : [Option<[u8; PSKLEN]>; 10],
        prologue        : &'a [u8],
        cipherstates    : CipherStates) -> Result<HandshakeState, SnowError> {

        if (s.is_on() && e.is_on()  && s.pub_len() != e.pub_len())
        || (s.is_on() && rs.is_on() && s.pub_len() >  rs.len())
        || (s.is_on() && re.is_on() && s.pub_len() >  re.len())
        {
            bail!(InitStage::ValidateKeyLengths);
        }

        let tokens = HandshakeTokens::try_from(&params.handshake)?;

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
            rng,
            symmetricstate,
            cipherstates,
            s,
            e,
            fixed_ephemeral,
            rs,
            re,
            initiator,
            params,
            psks,
            my_turn: initiator,
            message_patterns: tokens.msg_patterns,
            pattern_position: 0,
        })
    }

    pub(crate) fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&self, local_s: bool, remote_s: bool) -> Result<[u8; MAXDHLEN], SnowError> {
        if !((!local_s  || self.s.is_on())  &&
             ( local_s  || self.e.is_on())  &&
             (!remote_s || self.rs.is_on()) &&
             ( remote_s || self.re.is_on()))
        {
            bail!(StateProblem::MissingKeyMaterial);
        }
        let mut dh_out = [0u8; MAXDHLEN];
        let (dh, key) = match (local_s, remote_s) {
            (true,  true ) => (&self.s, &self.rs),
            (true,  false) => (&self.s, &self.re),
            (false, true ) => (&self.e, &self.rs),
            (false, false) => (&self.e, &self.re),
        };
        dh.dh(&**key, &mut dh_out).map_err(|_| SnowError::Dh)?;
        Ok(dh_out)
    }

    pub fn is_write_encrypted(&self) -> bool {
        self.symmetricstate.has_key()
    }

    #[must_use]
    pub fn write_handshake_message(&mut self,
                                  message: &[u8], 
                                  payload: &mut [u8]) -> Result<usize, SnowError> {
        self.symmetricstate.checkpoint();
        match self._write_handshake_message(message, payload) {
            Ok(res) => {
                self.pattern_position += 1;
                Ok(res)
            },
            Err(err) => {
                self.symmetricstate.rollback();
                Err(err)
            }
        }
    }

    fn _write_handshake_message(&mut self,
                         payload: &[u8],
                         message: &mut [u8]) -> Result<usize, SnowError> {
        if !self.my_turn {
            bail!(StateProblem::NotTurnToWrite);
        } else if self.pattern_position >= self.message_patterns.len() {
            bail!(StateProblem::HandshakeAlreadyFinished);
        }

        let mut byte_index = 0;
        let dh_len = self.dh_len();
        for token in self.message_patterns[self.pattern_position].iter() {
            match token {
                Token::E => {
                    if byte_index + self.e.pub_len() > message.len() {
                        bail!(SnowError::Input)
                    }

                    if !self.fixed_ephemeral {
                        self.e.generate(&mut *self.rng);
                    }
                    {
                        let pubkey = self.e.pubkey();
                        copy_slices!(pubkey, &mut message[byte_index..]);
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
                        bail!(StateProblem::MissingKeyMaterial);
                    } else if byte_index + self.s.pub_len() > message.len() {
                        bail!(SnowError::Input)
                    }

                    byte_index += self.symmetricstate.encrypt_and_mix_hash(
                        self.s.pubkey(),
                        &mut message[byte_index..]);
                },
                Token::Psk(n) => match self.psks[*n as usize] {
                    Some(psk) => {
                        self.symmetricstate.mix_key_and_hash(&psk);
                    },
                    None => {
                        bail!(StateProblem::MissingPsk);
                    }
                },
                Token::Dhee => {
                    let dh_out = self.dh(false, false)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                },
                Token::Dhes => {
                    let dh_out = self.dh(false, true)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
                Token::Dhse => {
                    let dh_out = self.dh(true, false)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
                Token::Dhss => {
                    let dh_out = self.dh(true, true)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
            }
        }

        if byte_index + payload.len() + TAGLEN > message.len() {
            bail!(SnowError::Input);
        }
        byte_index += self.symmetricstate.encrypt_and_mix_hash(payload, &mut message[byte_index..]);
        if byte_index > MAXMSGLEN {
            bail!(SnowError::Input);
        }
        if self.pattern_position == (self.message_patterns.len() - 1) {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        self.my_turn = false;
        Ok(byte_index)
    }

    pub fn read_handshake_message(&mut self,
                                  message: &[u8],
                                  payload: &mut [u8]) -> Result<usize, SnowError> {
        self.symmetricstate.checkpoint();
        match self._read_handshake_message(message, payload) {
            Ok(res) => {
                self.pattern_position += 1;
                Ok(res)
            },
            Err(err) => {
                self.symmetricstate.rollback();
                Err(err)
            }
        }
    }

    fn _read_handshake_message(&mut self,
                               message: &[u8], 
                               payload: &mut [u8]) -> Result<usize, SnowError> {
        if message.len() > MAXMSGLEN {
            bail!(SnowError::Input);
        }

        let last = self.pattern_position == (self.message_patterns.len() - 1);

        let dh_len = self.dh_len();
        let mut ptr = message;
            for token in self.message_patterns[self.pattern_position].iter() {
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
                        self.symmetricstate.decrypt_and_mix_hash(data, &mut self.rs[..dh_len]).map_err(|_| SnowError::Decrypt)?;
                        self.rs.enable();
                    },
                    Token::Psk(n) => {
                        match self.psks[n as usize] {
                            Some(psk) => {
                                self.symmetricstate.mix_key_and_hash(&psk);
                            },
                            None => {
                                bail!(StateProblem::MissingPsk);
                            }
                        }
                    },
                Token::Dhee => {
                    let dh_out = self.dh(false, false)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                },
                Token::Dhes => {
                    let dh_out = self.dh(true, false)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
                Token::Dhse => {
                    let dh_out = self.dh(false, true)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
                Token::Dhss => {
                    let dh_out = self.dh(true, true)?;
                    self.symmetricstate.mix_key(&dh_out[..dh_len]);
                }
            }
        }

        self.symmetricstate.decrypt_and_mix_hash(ptr, payload).map_err(|_| SnowError::Decrypt)?;
        self.my_turn = true;
        if last {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok(payload_len)
    }

    /// Set the PSK at the specified position.
    #[must_use]
    pub fn set_psk(&mut self, location: usize, key: &[u8]) -> Result<(), SnowError> {
        if key.len() != PSKLEN || self.psks.len() <= location {
            bail!(SnowError::Input);
        }

        let mut new_psk = [0u8; PSKLEN];
        new_psk.copy_from_slice(&key[..]);
        self.psks[location as usize] = Some(new_psk);

        Ok(())
    }
 
    /// Get the remote party's static public key, if available.
    /// 
    /// Note: will return `None` if either the chosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known (as can be the case in the `XX`
    /// pattern, for example).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.as_option_ref().map(|rs| &rs[..self.dh_len()])
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    pub fn is_finished(&self) -> bool {
        self.pattern_position == self.message_patterns.len()
    }
}
