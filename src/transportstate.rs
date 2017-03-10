extern crate rustc_serialize;
extern crate arrayvec;

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
        Ok(cipher.encrypt(payload, message))
    }

    pub fn read_transport_message(&mut self,
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, NoiseError> {
        let cipher = if self.initiator { &mut self.cipherstates.1 } else { &mut self.cipherstates.0 };
        cipher.decrypt(payload, message).map_err(|_| NoiseError::DecryptError)
    }
}
