extern crate arrayvec;

use params::HandshakePattern;
use error::NoiseError;
use cipherstate::CipherStates;
use constants::{MAXMSGLEN, TAGLEN};

/// A state machine encompassing the transport phase of a Noise session, using the two
/// `CipherState`s (for sending and receiving) that were spawned from the `SymmetricState`'s
/// `Split()` method, called after a handshake has been finished.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct TransportState {
    pub cipherstates: CipherStates,
    pattern: HandshakePattern,
    initiator: bool,
}

impl TransportState {
    pub fn new(cipherstates: CipherStates, pattern: HandshakePattern, initiator: bool) -> Self {
        TransportState {
            cipherstates: cipherstates,
            pattern: pattern,
            initiator: initiator,
        }
    }

    pub fn write_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, NoiseError> {
        if !self.initiator && self.pattern.is_oneway() {
            return Err(NoiseError::StateError("receiver in one-way pattern can't send"));
        } else if payload.len() + TAGLEN > MAXMSGLEN {
            return Err(NoiseError::InputError("message len exceeds Noise max"));
        } else if payload.len() + TAGLEN > message.len() {
            return Err(NoiseError::InputError("output buffer too small"));
        }

        let cipher = if self.initiator { &mut self.cipherstates.0 } else { &mut self.cipherstates.1 };
        Ok(cipher.encrypt(payload, message))
    }

    pub fn read_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, NoiseError> {
        if self.initiator && self.pattern.is_oneway() {
            return Err(NoiseError::StateError("sender in one-way pattern can't receive"));
        }
        let cipher = if self.initiator { &mut self.cipherstates.1 } else { &mut self.cipherstates.0 };
        cipher.decrypt(payload, message).map_err(|_| NoiseError::DecryptError)
    }
}
