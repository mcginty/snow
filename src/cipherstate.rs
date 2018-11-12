use std::u64;
use constants::TAGLEN;
use error::{SnowError, InitStage};
use types::Cipher;

pub struct CipherState {
    cipher : Box<Cipher>,
    n : u64,
    has_key : bool,
}

impl CipherState {
    pub fn new(cipher: Box<Cipher>) -> Self {
        Self {
            cipher,
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

    fn encrypt_with_nonce(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
	self.cipher.encrypt(nonce, authtext, plaintext, out)
    }

    pub fn encrypt_with_max_nonce(&self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        self.encrypt_with_nonce(u64::MAX, authtext, plaintext, out)
    }

    // TODO: don't panic
    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
        let n = self.n.clone();
        let len = self.encrypt_with_nonce(n, authtext, plaintext, out);
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
    pub fn new(initiator: CipherState, responder: CipherState) -> Result<Self, SnowError> {
        if initiator.name() != responder.name() {
            bail!(InitStage::ValidateCipherTypes);
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

pub struct StatelessCipherState {
    cipher : Box<Cipher>,
    has_key : bool,
}

impl StatelessCipherState {
    pub fn new(cipher: Box<Cipher>) -> Self {
        Self {
            cipher,
            has_key: false
        }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.name()
    }

    pub fn set(&mut self, key: &[u8]) {
        self.cipher.set(key);
        self.has_key = true;
    }

    // TODO: don't panic
    pub fn encrypt_ad(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
        self.cipher.encrypt(nonce, authtext, plaintext, out)
    }

    pub fn decrypt_ad(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        if (ciphertext.len() < TAGLEN) || (out.len() < (ciphertext.len() - TAGLEN) || !self.has_key) {
            return Err(())
        }

        self.cipher.decrypt(nonce, authtext, ciphertext, out)
    }

    pub fn encrypt(&self, nonce: u64, plaintext: &[u8], out: &mut[u8]) -> usize {
        self.encrypt_ad(nonce, &[], plaintext, out)
    }

    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        self.decrypt_ad(nonce, &[], ciphertext, out)
    }

    pub fn rekey(&mut self, key: &[u8]) {
        self.cipher.set(key);
    }
}

impl From<CipherState> for StatelessCipherState {
    fn from(other: CipherState) -> Self {
        Self {
            cipher: other.cipher,
            has_key: other.has_key
        }
    }
}

pub struct StatelessCipherStates(pub StatelessCipherState, pub StatelessCipherState);

impl From<CipherStates> for StatelessCipherStates {
    fn from(other: CipherStates) -> Self {
        StatelessCipherStates(other.0.into(), other.1.into())
    }
}

impl StatelessCipherStates {
    pub fn new(initiator: StatelessCipherState, responder: StatelessCipherState) -> Result<Self, SnowError> {
        if initiator.name() != responder.name() {
            bail!(InitStage::ValidateCipherTypes);
        }

        Ok(StatelessCipherStates(initiator, responder))
    }

    pub fn rekey_initiator(&mut self, key: &[u8]) {
        self.0.rekey(key)
    }


    pub fn rekey_responder(&mut self, key: &[u8]) {
        self.1.rekey(key)
    }
}
