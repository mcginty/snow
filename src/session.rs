use cipherstate::CipherState;
use crypto_types::CipherType;
use handshakestate::{CipherStates, HandshakeState};
use std::ops::{Deref, DerefMut};


pub struct NoiseSession<S> {
    state: S,
}

impl From<NoiseSession<HandshakeState>> for NoiseSession<CipherStates> {
    fn from(old: NoiseSession<HandshakeState>) -> Self {
        let cipherstates = old.state.finish();
        NoiseSession {
            state: cipherstates
        }
    }
}

impl From<HandshakeState> for NoiseSession<HandshakeState> {
    fn from(handshake_state: HandshakeState) -> Self {
        Self {
            state: handshake_state
        }
    }
}

impl NoiseSession<HandshakeState> {
    pub fn complete_handshake(self) -> NoiseSession<CipherStates> {
        self.into()
    }
}

impl<S> Deref for NoiseSession<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.state
    }
}

impl<S> DerefMut for NoiseSession<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.state
    }
}