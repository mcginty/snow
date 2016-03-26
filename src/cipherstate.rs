
use crypto_types::*;

pub trait CipherStateType {
    fn name(&self, out: &mut [u8]) -> usize;
    fn clear(&mut self);
    fn is_empty(&self) -> bool;
    fn set(&mut self, key: &[u8], nonce: u64);
    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]);
    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool;
}

pub struct CipherState<C: CipherType> {
    cipher : C,
    n : u64,
    empty : bool
}

impl<C: CipherType> CipherStateType for CipherState<C> {

    fn name(&self, out: &mut [u8]) -> usize {
        self.cipher.name(out)
    }

    fn clear(&mut self) {
        self.cipher.clear();
        self.n = 0;
        self.empty = true;
    }

    fn is_empty(&self) -> bool {
        self.empty
    }

    fn set(&mut self, key: &[u8], nonce: u64) {
        self.cipher.set(key);
        self.n = nonce;
        self.empty = false;
    }

    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        assert!(!self.empty);
        self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n += 1;
        if self.n == 0 {
            self.clear();
        }
    }

    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(!self.empty);
        let result = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n += 1;
        if self.n == 0 {
            self.clear();
        }
        result
    }

    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) {
        assert!(!self.empty);
        self.cipher.encrypt(self.n, &[0u8;0], plaintext, out);
        self.n += 1;
        if self.n == 0 {
            self.clear();
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(!self.empty);
        let result = self.cipher.decrypt(self.n, &[0u8;0], ciphertext, out);
        self.n += 1;
        if self.n == 0 {
            self.clear();
        }
        result
    }
}

