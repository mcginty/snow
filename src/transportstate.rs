use crate::{
    cipherstate::CipherStates,
    constants::{MAXDHLEN, MAXMSGLEN, TAGLEN},
    error::{Error, StateProblem},
    handshakestate::HandshakeState,
    params::HandshakePattern,
    utils::Toggle,
};
use std::{convert::TryFrom, fmt};

/// A state machine encompassing the transport phase of a Noise session, using the two
/// `CipherState`s (for sending and receiving) that were spawned from the `SymmetricState`'s
/// `Split()` method, called after a handshake has been finished.
///
/// Also see: [the relevant Noise spec section](https://noiseprotocol.org/noise.html#the-handshakestate-object).
pub struct TransportState {
    cipherstates: CipherStates,
    pattern:      HandshakePattern,
    dh_len:       usize,
    rs:           Toggle<[u8; MAXDHLEN]>,
    initiator:    bool,
}

impl TransportState {
    pub(crate) fn new(handshake: HandshakeState) -> Result<Self, Error> {
        if !handshake.is_handshake_finished() {
            return Err(StateProblem::HandshakeNotFinished.into());
        }

        let dh_len = handshake.dh_len();
        let HandshakeState { cipherstates, params, rs, initiator, .. } = handshake;
        let pattern = params.handshake.pattern;

        Ok(TransportState { cipherstates, pattern, dh_len, rs, initiator })
    }

    /// Get the remote party's static public key, if available.
    ///
    /// Note: will return `None` if either the chosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known (as can be the case in the `XX`
    /// pattern, for example).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.get().map(|rs| &rs[..self.dh_len])
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and write it to the `message` buffer.
    ///
    /// Returns the number of bytes written to `message`.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        if !self.initiator && self.pattern.is_oneway() {
            return Err(StateProblem::OneWay.into());
        } else if payload.len() + TAGLEN > MAXMSGLEN || payload.len() + TAGLEN > message.len() {
            return Err(Error::Input);
        }

        let cipher =
            if self.initiator { &mut self.cipherstates.0 } else { &mut self.cipherstates.1 };
        cipher.encrypt(payload, message)
    }

    /// Read a noise message from `message` and write the payload to the `payload` buffer.
    ///
    /// Returns the number of bytes written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Decrypt` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// Will result in `StateProblem::Exhausted` if the max nonce overflows.
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        if self.initiator && self.pattern.is_oneway() {
            return Err(StateProblem::OneWay.into());
        }
        let cipher =
            if self.initiator { &mut self.cipherstates.1 } else { &mut self.cipherstates.0 };

        cipher.decrypt(message, payload)
    }

    /// Generate a new key for the egress symmetric cipher according to Section 4.2
    /// of the Noise Specification. Synchronizing timing of rekey between initiator and
    /// responder is the responsibility of the application, as described in Section 11.3
    /// of the Noise Specification.
    pub fn rekey_outgoing(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_initiator()
        } else {
            self.cipherstates.rekey_responder()
        }
    }

    /// Generate a new key for the ingress symmetric cipher according to Section 4.2
    /// of the Noise Specification. Synchronizing timing of rekey between initiator and
    /// responder is the responsibility of the application, as described in Section 11.3
    /// of the Noise Specification.
    pub fn rekey_incoming(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_responder()
        } else {
            self.cipherstates.rekey_initiator()
        }
    }

    /// Set a new key for the one or both of the initiator-egress and responder-egress symmetric ciphers.
    pub fn rekey_manually(&mut self, initiator: Option<&[u8]>, responder: Option<&[u8]>) {
        if let Some(key) = initiator {
            self.rekey_initiator_manually(key);
        }
        if let Some(key) = responder {
            self.rekey_responder_manually(key);
        }
    }

    /// Set a new key for the initiator-egress symmetric cipher.
    pub fn rekey_initiator_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_initiator_manually(key)
    }

    /// Set a new key for the responder-egress symmetric cipher.
    pub fn rekey_responder_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_responder_manually(key)
    }

    /// Set the forthcoming *inbound* nonce value. Useful for using noise on lossy transports.
    pub fn set_receiving_nonce(&mut self, nonce: u64) {
        if self.initiator {
            self.cipherstates.1.set_nonce(nonce);
        } else {
            self.cipherstates.0.set_nonce(nonce);
        }
    }

    /// Get the forthcoming inbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `Error::State` if not in transport mode.
    pub fn receiving_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.1.nonce()
        } else {
            self.cipherstates.0.nonce()
        }
    }

    /// Get the forthcoming outbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `Error::State` if not in transport mode.
    pub fn sending_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.0.nonce()
        } else {
            self.cipherstates.1.nonce()
        }
    }

    /// Check if this session was started with the "initiator" role.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
}

impl fmt::Debug for TransportState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TransportState").finish()
    }
}

impl TryFrom<HandshakeState> for TransportState {
    type Error = Error;

    fn try_from(old: HandshakeState) -> Result<Self, Self::Error> {
        TransportState::new(old)
    }
}
