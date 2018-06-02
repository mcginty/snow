use constants::*;
use failure::Error;
use error::{SnowError, InitStage};
use types::Cipher;
use std::sync::{Arc, RwLock};

pub struct CipherState {
    cipher : Box<Cipher + Send + Sync>,
    n : u64,
    has_key : bool,
}

impl CipherState {
    pub fn new(cipher: Box<Cipher + Send + Sync>) -> Self {
        Self {
            cipher: cipher,
            n: 0,
            has_key: false
        }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.name()
    }

    pub fn set(&mut self, key: &[u8], n: u64) {
        self.cipher.set(key);
        self.n = n;
        self.has_key = true;
    }

    // TODO: don't panic
    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
        let len = self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n = self.n.checked_add(1).unwrap();
        len
    }

    pub fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        if (ciphertext.len() < TAGLEN) || (out.len() < (ciphertext.len() - TAGLEN) || !self.has_key) {
            return Err(())
        }

        let len = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n = self.n.checked_add(1).unwrap();
        len
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) -> usize {
        self.encrypt_ad(&[0u8;0], plaintext, out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        self.decrypt_ad(&[0u8;0], ciphertext, out)
    }

    pub fn rekey(&mut self, key: &[u8]) {
        self.cipher.set(key);
    }

    pub fn nonce(&self) -> u64 {
        self.n
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }
}

pub struct CipherStates(pub CipherState, pub CipherState);

impl CipherStates {
    pub fn new(initiator: CipherState, responder: CipherState) -> Result<Self, Error> {
        if initiator.name() != responder.name() {
            bail!(SnowError::Init { reason: InitStage::ValidateCipherTypes });
        }

        Ok(CipherStates(initiator, responder))
    }

    pub fn rekey_initiator(&mut self, key: &[u8]) {
        self.0.rekey(key)
    }


    pub fn rekey_responder(&mut self, key: &[u8]) {
        self.1.rekey(key)
    }
}

#[derive(Clone)]
pub struct AsyncCipherState {
    cipher : Arc<RwLock<Box<Cipher + Send + Sync>>>,
    has_key : bool,
}

impl AsyncCipherState {
    pub fn new(cipher: Box<Cipher + Send + Sync>) -> Self {
        Self {
            cipher: Arc::new(RwLock::new(cipher)),
            has_key: false
        }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.read().unwrap().name()
    }

    pub fn set(&mut self, key: &[u8]) {
        self.cipher.write().unwrap().set(key);
        self.has_key = true;
    }

    // TODO: don't panic
    pub fn encrypt_ad(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
        let len = self.cipher.read().unwrap().encrypt(nonce, authtext, plaintext, out);
        len
    }

    pub fn decrypt_ad(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        if (ciphertext.len() < TAGLEN) || (out.len() < (ciphertext.len() - TAGLEN) || !self.has_key) {
            return Err(())
        }

        let len = self.cipher.read().unwrap().decrypt(nonce, authtext, ciphertext, out);
        len
    }

    pub fn encrypt(&self, nonce: u64, plaintext: &[u8], out: &mut[u8]) -> usize {
        self.encrypt_ad(nonce, &[], plaintext, out)
    }

    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        self.decrypt_ad(nonce, &[], ciphertext, out)
    }

    pub fn rekey(&mut self, key: &[u8]) {
        self.cipher.write().unwrap().set(key);
    }
}

impl From<CipherState> for AsyncCipherState {
    fn from(other: CipherState) -> Self {
        let has_key = other.has_key;
        Self {
            cipher: Arc::new(RwLock::new(other.cipher)),
            has_key
        }
    }
}

#[derive(Clone)]
pub struct AsyncCipherStates(pub AsyncCipherState, pub AsyncCipherState);

impl From<CipherStates> for AsyncCipherStates {
    fn from(other: CipherStates) -> Self {
        AsyncCipherStates(other.0.into(), other.1.into())
    }
}

impl AsyncCipherStates {
    pub fn new(initiator: AsyncCipherState, responder: AsyncCipherState) -> Result<Self, Error> {
        if initiator.name() != responder.name() {
            bail!(SnowError::Init { reason: InitStage::ValidateCipherTypes });
        }

        Ok(AsyncCipherStates(initiator, responder))
    }

    pub fn rekey_initiator(&mut self, key: &[u8]) {
        self.0.rekey(key)
    }


    pub fn rekey_responder(&mut self, key: &[u8]) {
        self.1.rekey(key)
    }
}