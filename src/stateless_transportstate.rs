use params::HandshakePattern;
use error::{SnowError, StateProblem};
use cipherstate::StatelessCipherStates;
use constants::{MAXDHLEN, MAXMSGLEN, TAGLEN};
use handshakestate::HandshakeState;
use utils::Toggle;
use std::fmt;

/// A state machine encompassing the transport phase of a Noise session, using the two
/// `CipherState`s (for sending and receiving) that were spawned from the `SymmetricState`'s
/// `Split()` method, called after a handshake has been finished.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct StatelessTransportState {
    pub cipherstates: StatelessCipherStates,
    pattern: HandshakePattern,
    dh_len: usize,
    rs: Toggle<[u8; MAXDHLEN]>,
    initiator: bool,
}

impl StatelessTransportState {
    pub fn new(handshake: HandshakeState) -> Result<Self, SnowError> {
        if !handshake.is_finished() {
            bail!(StateProblem::HandshakeNotFinished);
        }

        let dh_len = handshake.dh_len();
        let HandshakeState {cipherstates, params, rs, initiator, ..} = handshake;
        let pattern = params.handshake.pattern;

        Ok(Self {
            cipherstates: cipherstates.into(),
            pattern,
            dh_len,
            rs,
            initiator,
        })
    }

    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.as_option_ref().map(|rs| &rs[..self.dh_len])
    }

    pub fn write_transport_message(&mut self,
                                   nonce: u64,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, SnowError> {
        if !self.initiator && self.pattern.is_oneway() {
            bail!(StateProblem::OneWay);
        } else if payload.len() + TAGLEN > MAXMSGLEN || payload.len() + TAGLEN > message.len() {
            bail!(SnowError::Input);
        }

        let cipher = if self.initiator { &mut self.cipherstates.0 } else { &mut self.cipherstates.1 };
        Ok(cipher.encrypt(nonce, payload, message))
    }

    pub fn read_transport_message(&self,
                                  nonce: u64,
                                  payload: &[u8],
                                  message: &mut [u8]) -> Result<usize, SnowError> {
        if self.initiator && self.pattern.is_oneway() {
            bail!(SnowError::State { reason: StateProblem::OneWay });
        }
        let cipher = if self.initiator { &self.cipherstates.1 } else { &self.cipherstates.0 };
        cipher.decrypt(nonce, payload, message).map_err(|_| SnowError::Decrypt)
    }

    pub fn rekey_initiator(&mut self, key: &[u8]) {
        self.cipherstates.rekey_initiator(key)
    }

    pub fn rekey_responder(&mut self, key: &[u8]) {
        self.cipherstates.rekey_responder(key)
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
}

impl fmt::Debug for StatelessTransportState {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("StatelessTransportState").finish()
    }
}
