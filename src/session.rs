use error::NoiseError;
use handshakestate::HandshakeState;
use std::convert::{TryFrom, TryInto};
use transportstate::*;

/// Methods that must be implemented across all states in the NoiseSession state machine.
pub trait NoiseSessionState {
    fn is_payload_encrypted(&self) -> bool;
    fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError>;
    fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError>;
}

/// The high-level state machine for the flow from handshake to transport stages.
pub struct NoiseSession<S> where S: NoiseSessionState {
    state: S,
}

impl TryFrom<NoiseSession<HandshakeState>> for NoiseSession<TransportState> {
    type Err = NoiseError;

    fn try_from(old: NoiseSession<HandshakeState>) -> Result<Self, Self::Err> {
        let initiator = old.state.is_initiator();
        let cipherstates = old.state.finish()?;
        Ok(NoiseSession {
            state: TransportState::new(cipherstates, initiator)
        })
    }
}

impl From<HandshakeState> for NoiseSession<HandshakeState> {
    fn from(handshake_state: HandshakeState) -> Self {
        Self {
            state: handshake_state
        }
    }
}

impl NoiseSessionState for HandshakeState {
    fn is_payload_encrypted(&self) -> bool {
        self.is_write_encrypted()
    }

    fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.write_handshake_message(payload, output)
    }

    fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        self.read_handshake_message(input, payload)
    }
}

impl NoiseSessionState for TransportState {
    fn is_payload_encrypted(&self) -> bool {
        true
    }

    fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.write_transport_message(payload, output)
    }

    fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        self.read_transport_message(input, payload)
    }
}

impl NoiseSession<HandshakeState> {
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_finished()
    }

    pub fn into_transport_mode(self) -> Result<NoiseSession<TransportState>, NoiseError> {
        if !self.state.is_finished() {
            Err(NoiseError::StateError("handshake not yet finished"))
        } else {
            self.try_into()
        }
    }
}

impl<S: NoiseSessionState> NoiseSessionState for NoiseSession<S> {
    fn is_payload_encrypted(&self) -> bool {
        self.state.is_payload_encrypted()
    }

    fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.state.write_message(payload, output)
    }

    fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        self.state.read_message(input, payload)
    }
}