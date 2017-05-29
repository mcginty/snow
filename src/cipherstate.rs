use error::{self, ErrorKind, InitStage};
use types::Cipher;

pub struct CipherState {
    cipher : Box<Cipher>,
    n : u64,
    has_key : bool,
}

impl CipherState {
    pub fn new(cipher: Box<Cipher>) -> Self {
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

    // TODO: don't panic
    pub fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        assert!(self.has_key);
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
        self.cipher.set(&key);
    }
}

pub struct CipherStates(pub CipherState, pub CipherState);

impl CipherStates {
    pub fn new(initiator: CipherState, responder: CipherState) -> error::Result<Self> {
        if initiator.name() != responder.name() {
            bail!(ErrorKind::Init(InitStage::ValidateCipherTypes));
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
