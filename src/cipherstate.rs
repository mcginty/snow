
use crypto_types::*;

pub trait CipherStateType {
    fn name(&self, out: &mut [u8]) -> usize;
    fn clear(&mut self);
    fn is_empty(&self) -> bool;
    fn set(&mut self, key: &[u8], n: u64);
    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]);
    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool;
}

#[derive(Default)]
pub struct CipherState<C: CipherType + Default> {
    cipher : C,
    n : u64,
    has_key : bool,
    overflow: bool
}

impl<C: CipherType + Default> CipherStateType for CipherState<C> {

    fn name(&self, out: &mut [u8]) -> usize {
        self.cipher.name(out)
    }

    fn clear(&mut self) {
        self.n = 0;
        self.has_key = false;
        self.overflow = false;
    }

    fn is_empty(&self) -> bool {
        !self.has_key
    }

    fn set(&mut self, key: &[u8], n: u64) {
        self.cipher.set(key);
        self.n = n;
        self.has_key = true;
        self.overflow = false;
    }

    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        assert!(self.has_key && !self.overflow);
        self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n += 1;
        if self.n == 0 {
            self.overflow = true;
        }
    }

    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(self.has_key && !self.overflow);
        let result = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n += 1;
        if self.n == 0 {
            self.overflow = true;
        }
        result
    }

    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) {
        self.encrypt_ad(&[0u8;0], plaintext, out)
    }

    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool {
        self.decrypt_ad(&[0u8;0], ciphertext, out)
    }
}

