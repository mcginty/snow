use error::NoiseError;
use handshakestate::HandshakeState;
use std::convert::{TryFrom, TryInto};
use transportstate::*;

pub enum Session {
    Handshake(HandshakeState),
    Transport(TransportState),
}

impl Session {
    pub fn is_payload_encrypted(&self) -> bool {
        match *self {
            Session::Handshake(ref state) => state.is_write_encrypted(),
            Session::Transport(_) => true,
        }
    }

    pub fn is_handshake_finished(&self) -> bool {
        match *self {
            Session::Handshake(ref state) => state.is_finished(),
            Session::Transport(_) => true,
        }
    }

    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        match *self {
            Session::Handshake(ref mut state) => state.write_handshake_message(payload, output),
            Session::Transport(ref mut state) => state.write_transport_message(payload, output),
        }
    }

    pub fn read_message(&mut self, input: &[u8], payload: &mut [u8]) -> Result<usize, NoiseError> {
        match *self {
            Session::Handshake(ref mut state) => state.read_handshake_message(input, payload),
            Session::Transport(ref mut state) => state.read_transport_message(input, payload),
        }
    }

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

