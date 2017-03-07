extern crate rustc_serialize;
extern crate arrayvec;

use self::arrayvec::{ArrayVec, ArrayString};
use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;
use symmetricstate::*;
use patterns::*;
use std::ops::{Deref, DerefMut};
use handshakestate::*;

pub struct TransportState {
    pub cipherstates: CipherStates,
    initiator: bool,
}

impl TransportState {
    pub fn new(cipherstates: CipherStates, initiator: bool) -> Self {
        TransportState {
            cipherstates: cipherstates,
            initiator: initiator,
        }
    }

    pub fn write_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, NoiseError> {
        let cipher = if self.initiator { &mut self.cipherstates.0 } else { &mut self.cipherstates.1 };
        cipher.encrypt(payload, message);
        Ok(payload.len() + 12) // TODO modify cipher interface to return len of ciphertext
    }

    pub fn read_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, NoiseError> {
        let cipher = if self.initiator { &mut self.cipherstates.1 } else { &mut self.cipherstates.0 };
        cipher.decrypt(payload, message);
        Ok(payload.len() - 12) // TODO modify cipher interface to return len of ciphertext
    }
}
