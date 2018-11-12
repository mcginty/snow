use error::{SnowError, StateProblem};
use handshakestate::HandshakeState;
#[cfg(feature = "nightly")] use std::convert::{TryFrom, TryInto};
#[cfg(not(feature = "nightly"))] use utils::{TryFrom, TryInto};
use transportstate::TransportState;
use stateless_transportstate::StatelessTransportState;

/// A state machine for the entire Noise session.
///
/// Enums provide a convenient interface as it's how Rust implements union structs, meaning this is
/// a sized object.
// TODO: check up on memory usage, since this clippy warning seems like a legit perf issue.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
#[derive(Debug)]
pub enum Session {
    /// A session in the handshake stage (the starting state).
    Handshake(HandshakeState),

    /// A session after having completed a handshake, in general-purpose trasport mode.
    Transport(TransportState),

    /// A session after having completed a handshake, in explicit-nonce trasport mode.
    StatelessTransport(StatelessTransportState),
}

impl Session {
    /// This method will return `true` if the *previous* write payload was encrypted.
    ///
    /// See [Payload Security Properties](http://noiseprotocol.org/noise.html#payload-security-properties)
    /// for more information on the specific properties of your chosen handshake pattern.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = Builder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///     .build_initiator()?;
    ///
    /// // write message...
    ///
    /// assert!(session.was_write_payload_encrypted());
    /// ```
    pub fn was_write_payload_encrypted(&self) -> bool {
        match *self {
            Session::Handshake(ref state)  => state.was_write_payload_encrypted(),
            Session::Transport(_)          => true,
            Session::StatelessTransport(_) => true,
        }
    }

    /// True if the handshake is finished and the Session state machine is ready to be transitioned
    /// to transport mode. This function also returns a vacuous true if already in transport mode.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = Builder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///     .build_initiator()?;
    ///
    /// if (session.is_handshake_finished()) {
    ///     session = session.into_transport_mode()?;
    /// }
    /// ```
    pub fn is_handshake_finished(&self) -> bool {
        match *self {
            Session::Handshake(ref state)  => state.is_finished(),
            Session::Transport(_)          => true,
            Session::StatelessTransport(_) => true,
        }
    }

    /// Will report if the session has the initiator role (i.e. was built with [`Builder.build_initiator()`]).
    ///
    /// [`Builder.build_initiator()`]: struct.Builder.html#method.build_initiator
    pub fn is_initiator(&self) -> bool {
        match *self {
            Session::Handshake(ref state)          => state.is_initiator(),
            Session::Transport(ref state)          => state.is_initiator(),
            Session::StatelessTransport(ref state) => state.is_initiator(),
        }
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `output` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    #[must_use]
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, SnowError> {
        match *self {
            Session::Handshake(ref mut state) => state.write_handshake_message(payload, output),
            Session::Transport(ref mut state) => state.write_transport_message(payload, output),
            Session::StatelessTransport(_)    => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Construct a message from `payload` with an explicitly provided nonce and write it to the
    /// `output` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    ///
    /// Will result in `SnowError::StateProblem` if not in stateless transport mode.
    #[must_use]
    pub fn write_message_with_nonce(&self, nonce: u64, payload: &[u8], output: &mut [u8]) -> Result<usize, SnowError> {
        match *self {
            Session::StatelessTransport(ref state) => state.write_transport_message(nonce, payload, output),
            _                                      => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Reads a noise message from `input`
    ///
    /// Returns the size of the payload written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::Decrypt` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// # Panics
    ///
    /// This function will panic if there is no key, or if there is a nonce overflow.
    #[must_use]
    pub fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, SnowError> {
        match *self {
            Session::Handshake(ref mut state) => state.read_handshake_message(input, payload),
            Session::Transport(ref mut state) => state.read_transport_message(input, payload),
            Session::StatelessTransport(_)    => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `output` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    ///
    /// Will result in `SnowError::StateProblem` if not in stateless transport mode.
    #[must_use]
    pub fn read_message_with_nonce(&self, nonce: u64, input: &[u8], payload: &mut [u8]) -> Result<usize, SnowError> {
        match *self {
            Session::StatelessTransport(ref state) => state.read_transport_message(nonce, input, payload),
            _                                      => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Set a new key for the one or both of the initiator-egress and responder-egress symmetric ciphers.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::State` if not in transport mode.
    #[must_use]
    pub fn rekey(&mut self, initiator: Option<&[u8]>, responder: Option<&[u8]>) -> Result<(), SnowError> {
        match *self {
            Session::Handshake(_) => bail!(StateProblem::HandshakeNotFinished),
            Session::Transport(ref mut state) => {
                if let Some(key) = initiator {
                    state.rekey_initiator(key);
                }
                if let Some(key) = responder {
                    state.rekey_responder(key);
                }
                Ok(())
            },
            Session::StatelessTransport(ref mut state) => {
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

    /// Implement a deterministic rekey as per section 4.2 of the Noise protocol framework specification.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::State` if not in transport mode.
    #[must_use]
    pub fn deterministic_rekey(&mut self) -> Result<(), SnowError> {
        match *self {
            Session::Handshake(_)              => bail!(StateProblem::HandshakeNotFinished),
            Session::Transport(ref mut state)  => {
                let mut initiator_out = vec![0u8; 32];
                let mut responder_out = vec![0u8; 32];
                let auth = vec![0u8; 0];
                let payload = vec![0u8; 0];
                let _ = state.cipherstates.0.encrypt_with_max_nonce(&auth, &payload, &mut initiator_out);
                let _ = state.cipherstates.0.encrypt_with_max_nonce(&auth, &payload, &mut responder_out);
                state.rekey_initiator(&initiator_out);
                state.rekey_responder(&responder_out);
            },
            Session::StatelessTransport(_)     => bail!(StateProblem::StatelessTransportMode),
        }
        Ok(())
    }

    /// Get the forthcoming inbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::State` if not in transport mode.
    pub fn receiving_nonce(&self) -> Result<u64, SnowError> {
        match *self {
            Session::Handshake(_)          => bail!(StateProblem::HandshakeNotFinished),
            Session::Transport(ref state)  => Ok(state.receiving_nonce()),
            Session::StatelessTransport(_) => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Get the forthcoming outbound nonce value.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::State` if not in transport mode.
    pub fn sending_nonce(&self) -> Result<u64, SnowError> {
        match *self {
            Session::Handshake(_)          => bail!(StateProblem::HandshakeNotFinished),
            Session::Transport(ref state)  => Ok(state.sending_nonce()),
            Session::StatelessTransport(_) => bail!(StateProblem::StatelessTransportMode),
        }
    }

    /// Get the remote static key that was possibly encrypted in the first payload.
    ///
    /// Returns a slice of length `Dh.pub_len()` (i.e. DHLEN for the chosen DH function).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        match *self {
            Session::Handshake(ref state)          => state.get_remote_static(),
            Session::Transport(ref state)          => state.get_remote_static(),
            Session::StatelessTransport(ref state) => state.get_remote_static(),
        }
    }

    /// Get the handshake hash.
    ///
    /// Returns a slice of length `Hasher.hash_len()` (i.e. HASHLEN for the chosen Hash function).
    pub fn get_handshake_hash(&self) -> Result<&[u8], SnowError> {
        match *self {
            Session::Handshake(ref state) => Ok(state.get_handshake_hash()),
            _                             => bail!(StateProblem::HandshakeAlreadyFinished),
        }
    }

    /// Set the preshared key at the specified location. It is up to the caller
    /// to correctly set the location based on the specified handshake - Snow
    /// won't stop you from placing a PSK in an unused slot.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::Input` if the PSK is not the right length or the location is out of bounds.
    /// Will result in `SnowError::State` if in transport mode.
    #[must_use]
    pub fn set_psk(&mut self, location: usize, key: &[u8]) -> Result<(), SnowError> {
        match *self {
            Session::Handshake(ref mut state) => state.set_psk(location, key),
            _                                 => bail!(StateProblem::HandshakeAlreadyFinished)
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
    /// Will result in `SnowError::State` if the handshake is not finished.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = Builder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///                   .build_initiator()?;
    ///
    /// // ... complete handshake ...
    ///
    /// session = session.into_transport_mode()?;
    /// ```
    ///
    pub fn into_transport_mode(self) -> Result<Self, SnowError> {
        match self {
            Session::Handshake(state) => {
                if !state.is_finished() {
                    bail!(StateProblem::HandshakeNotFinished)
                } else {
                    Ok(Session::Transport(state.try_into()?))
                }
            },
            _ => Ok(self)
        }
    }

    /// Transition the session into stateless (explicit nonce) transport mode.
    /// This is useful when using Noise over lossy transports.
    /// Like `into_transport_mode()`, this can only be done once the handshake has finished.
    ///
    /// Consumes the previous state, and returns the new transport state object, thereby freeing
    /// any material only used during the handshake phase.
    ///
    /// # Errors
    ///
    /// Will result in `SnowError::State` if the handshake is not finished.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = Builder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///                   .build_initiator()?;
    ///
    /// // ... complete handshake ...
    ///
    /// session = session.into_stateless_transport_mode()?;
    /// ```
    ///
    pub fn into_stateless_transport_mode(self) -> Result<Self, SnowError> {
        match self {
            Session::Handshake(state) => {
                if !state.is_finished() {
                    bail!(StateProblem::HandshakeNotFinished)
                } else {
                    Ok(Session::StatelessTransport(state.try_into()?))
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
    type Error = SnowError;

    fn try_from(old: HandshakeState) -> Result<Self, Self::Error> {
        TransportState::new(old)
    }
}

impl TryFrom<HandshakeState> for StatelessTransportState {
    type Error = SnowError;

    fn try_from(old: HandshakeState) -> Result<Self, Self::Error> {
        StatelessTransportState::new(old)
    }
}
