extern crate arrayvec;

use params::HandshakePattern;
use error::{ErrorKind, Result, StateProblem};
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
                                   message: &mut [u8]) -> Result<usize> {
        if !self.initiator && self.pattern.is_oneway() {
            bail!(ErrorKind::State(StateProblem::OneWay));
        } else if payload.len() + TAGLEN > MAXMSGLEN || payload.len() + TAGLEN > message.len() {
            bail!(ErrorKind::Input);
        }

        let cipher = if self.initiator { &mut self.cipherstates.0 } else { &mut self.cipherstates.1 };
        Ok(cipher.encrypt(payload, message))
    }

    pub fn read_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize> {
        if self.initiator && self.pattern.is_oneway() {
            bail!(ErrorKind::State(StateProblem::OneWay));
        }
        let cipher = if self.initiator { &mut self.cipherstates.1 } else { &mut self.cipherstates.0 };
        cipher.decrypt(payload, message).map_err(|_| ErrorKind::Decrypt.into())
    }

    pub fn rekey_initiator(&mut self, key: &[u8]) {
        self.cipherstates.rekey_initiator(key)
    }

    pub fn rekey_responder(&mut self, key: &[u8]) {
        self.cipherstates.rekey_responder(key)
    }

    /// Sets the *receiving* CipherState's nonce. Useful for using noise on lossy transports.
    pub fn set_receiving_nonce(&mut self, nonce: u64) {
        if self.initiator {
            self.cipherstates.1.set_nonce(nonce);
        } else {
            self.cipherstates.0.set_nonce(nonce);
        }
    }

    /// Gets the *receiving* CipherState's nonce. Useful for using noise on lossy transports.
    pub fn receiving_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.1.nonce()
        } else {
            self.cipherstates.0.nonce()
        }
    }

    pub fn sending_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.0.nonce()
        } else {
            self.cipherstates.1.nonce()
        }
    }
}
