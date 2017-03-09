extern crate rustc_serialize;

use utils::*;
use constants::*;
use crypto_types::*;
use cipherstate::*;

pub trait SymmetricStateType {
    fn cipher_name(&self) -> &'static str;
    fn hash_name(&self) -> &'static str;
    fn initialize(&mut self, handshake_name: &str);
    fn mix_key(&mut self, data: &[u8]);
    fn mix_hash(&mut self, data: &[u8]);
    fn mix_preshared_key(&mut self, psk: &[u8]);
    fn has_key(&self) -> bool;
    fn has_preshared_key(&self) -> bool;
    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize;
    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, ()>;
    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType);
}

pub struct SymmetricState {
    cipherstate : Box<CipherStateType>,
    hasher: Box<HashType>,
    h : [u8; MAXHASHLEN],
    ck: [u8; MAXHASHLEN],
    has_key: bool,
    has_preshared_key: bool,
}

impl SymmetricState {
    pub fn new(cipherstate: Box<CipherStateType>, hasher: Box<HashType>) -> SymmetricState
    {
        SymmetricState {
            cipherstate: cipherstate,
            hasher: hasher,
            h: [0u8; MAXHASHLEN],
            ck : [0u8; MAXHASHLEN],
            has_key: false,
            has_preshared_key: false,
        }
    }
}

impl SymmetricStateType for SymmetricState {

    fn cipher_name(&self) -> &'static str {
        self.cipherstate.name()
    }

    fn hash_name(&self) -> &'static str {
        self.hasher.name()
    }

    fn initialize(&mut self, handshake_name: &str) {
        if handshake_name.len() <= self.hasher.hash_len() {
            self.h = [0u8; MAXHASHLEN];
            self.h[..handshake_name.len()].copy_from_slice(handshake_name.as_bytes());
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name.as_bytes());
            self.hasher.result(&mut self.h);
        }
        copy_memory(&self.h, &mut self.ck);
        self.has_key = false;
        self.has_preshared_key = false;
    }

    fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.cipherstate.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.h);
    }

    fn mix_preshared_key(&mut self, psk: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.has_preshared_key = true;
    }

    fn has_key(&self) -> bool {
        self.has_key
    }

    fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let hash_len = self.hasher.hash_len();
        let output_len = if self.has_key {
            self.cipherstate.encrypt_ad(&self.h[..hash_len], plaintext, out) as usize
        } else {
            copy_memory(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        output_len
    }

    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.has_key {
            self.cipherstate.decrypt_ad(&self.h[..hash_len], data, out)?
        } else {
            copy_memory(data, out);
            data.len()
        };
        self.mix_hash(data);
        Ok(payload_len)
    }

    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], &[0u8; 0],
                         &mut hkdf_output.0,
                         &mut hkdf_output.1);
        child1.set(&hkdf_output.0[..CIPHERKEYLEN], 0);
        child2.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
    }


}
