use error::{Error, ErrorKind, Result, StateProblem};
use handshakestate::HandshakeState;
#[cfg(feature = "nightly")] use std::convert::{TryFrom, TryInto};
#[cfg(not(feature = "nightly"))] use utils::{TryFrom, TryInto};
use constants::MAXDHLEN;
use transportstate::*;

/// A state machine for the entire Noise session.
///
/// Enums provide a convenient interface as it's how Rust implements union structs, meaning this is
/// a sized object.
// TODO: check up on memory usage, since this clippy warning seems like a legit perf issue.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum Session {
    Handshake(HandshakeState),
    Transport(TransportState),
}

impl Session {
    /// If the payload will be encrypted or not. In a future version of Snow, this interface may
    /// change to more proactively prevent unauthenticated, plaintext payloads during handshakes.
    ///
    /// See [Payload Security Properties](http://noiseprotocol.org/noise.html#payload-security-properties)
    /// for more information.
    pub fn is_payload_encrypted(&self) -> bool {
        match *self {
            Session::Handshake(ref state) => state.is_write_encrypted(),
            Session::Transport(_) => true,
        }
    }

    /// True if the handshake is finished and the Session state machine is ready to be transitioned
    /// to transport mode. This function also returns a vacuous true if already in transport mode.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = NoiseBuilder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///                   .build_initiator()?;
    ///
    /// if (session.is_handshake_finished()) {
    ///     session = session.into_transport_mode()?;
    /// }
    /// ```
    pub fn is_handshake_finished(&self) -> bool {
        match *self {
            Session::Handshake(ref state) => state.is_finished(),
            Session::Transport(_) => true,
        }
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `output` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::InputError` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize> {
        match *self {
            Session::Handshake(ref mut state) => state.write_handshake_message(payload, output),
            Session::Transport(ref mut state) => state.write_transport_message(payload, output),
        }
    }

    /// Reads a noise message from `input`
    ///
    /// Returns the size of the payload written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::DecryptError` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// # Panics
    ///
    /// This function will panic if there is no key, or if there is a nonce overflow.
    pub fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize> {
        match *self {
            Session::Handshake(ref mut state) => state.read_handshake_message(input, payload),
            Session::Transport(ref mut state) => state.read_transport_message(input, payload),
        }
    }

    /// Set a new key for the one or both of the initiator-egress and responder-egress symmetric ciphers.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::StateError` if not in transport mode.
    pub fn rekey(&mut self, initiator: Option<&[u8]>, responder: Option<&[u8]>) -> Result<()> {
        match *self {
            Session::Handshake(_) => Err(ErrorKind::State(StateProblem::HandshakeNotFinished).into()),
            Session::Transport(ref mut state) => {
                if let Some(key) = initiator {
                    state.rekey_initiator(key);
                }
                if let Some(key) = responder {
                    state.rekey_responder(key);
                }
                Ok(())
            },
        }
    }

    /// Get the forthcoming inbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::StateError` if not in transport mode.
    pub fn receiving_nonce(&self) -> Result<u64> {
        match *self {
            Session::Handshake(_) => Err(ErrorKind::State(StateProblem::HandshakeNotFinished).into()),
            Session::Transport(ref state) => Ok(state.receiving_nonce())
        }
    }

    /// Get the forthcoming outbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::StateError` if not in transport mode.
    pub fn sending_nonce(&self) -> Result<u64> {
        match *self {
            Session::Handshake(_) => Err(ErrorKind::State(StateProblem::HandshakeNotFinished).into()),
            Session::Transport(ref state) => Ok(state.sending_nonce())
        }
    }

    /// Get the remote static key that was possibly encrypted in the first payload
    ///
    /// # Caveat
    ///
    /// This currently does not work *after* transitioning into the transport state.
    pub fn get_remote_static(&self) -> Option<&[u8; MAXDHLEN]> {
        match *self {
            Session::Handshake(ref state) => state.get_remote_static(),
            Session::Transport(_) => None
        }
    }

    /// Set the forthcoming incoming nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::StateError` if not in transport mode.
    pub fn set_receiving_nonce(&mut self, nonce: u64) -> Result<()> {
        match *self {
            Session::Handshake(_) => Err(ErrorKind::State(StateProblem::HandshakeNotFinished).into()),
            Session::Transport(ref mut state) => Ok(state.set_receiving_nonce(nonce))
        }
    }

    /// Transition the session into transport mode. This can only be done once the handshake
    /// has finished.
    ///
    /// Consumes the previous state, and returns the new transport state object, thereby freeing
    /// any material only used during the handshake phase.
    ///
    /// # Errors
    ///
    /// Will result in `NoiseError::StateError` if the handshake is not finished.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = NoiseBuilder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///                   .build_initiator()?;
    ///
    /// // ... complete handshake ...
    ///
    /// session = session.into_transport_mode()?;
    /// ```
    ///
    pub fn into_transport_mode(self) -> Result<Self> {
        match self {
            Session::Handshake(state) => {
                if !state.is_finished() {
                    Err(ErrorKind::State(StateProblem::HandshakeNotFinished).into())
                } else {
                    Ok(Session::Transport(state.try_into()?))
                }
            },
            _ => Ok(self)
        }
    }
}

impl Into<Session> for HandshakeState {
    fn into(self) -> Session {
        Session::Handshake(self)
    }
}

impl TryFrom<HandshakeState> for TransportState {
    type Error = Error;

    fn try_from(old: HandshakeState) -> Result<Self> {
        let initiator = old.is_initiator();
        let (cipherstates, handshake) = old.finish()?;
        Ok(TransportState::new(cipherstates, handshake.pattern, initiator))
    }
}

