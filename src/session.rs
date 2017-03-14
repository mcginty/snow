use error::NoiseError;
use handshakestate::HandshakeState;
use std::convert::{TryFrom, TryInto};
use transportstate::*;

/// A state machine for the entire Noise session.
///
/// Enums provide a convenient interface as it's how Rust implements union structs, meaning this is
/// a sized object.
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
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
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
    pub fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        match *self {
            Session::Handshake(ref mut state) => state.read_handshake_message(input, payload),
            Session::Transport(ref mut state) => state.read_transport_message(input, payload),
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
    pub fn into_transport_mode(self) -> Result<Self, NoiseError> {
        match self {
            Session::Handshake(state) => {
                if !state.is_finished() {
                    Err(NoiseError::StateError("handshake not yet finished"))
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
    type Err = NoiseError;

    fn try_from(old: HandshakeState) -> Result<Self, Self::Err> {
        let initiator = old.is_initiator();
        let cipherstates = old.finish()?;
        Ok(TransportState::new(cipherstates, initiator))
    }
}

