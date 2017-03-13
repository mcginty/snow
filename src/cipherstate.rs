
use types::*;

pub trait CipherStateType {
    fn name(&self) -> &'static str;
    fn set(&mut self, key: &[u8], n: u64);
    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize;
    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()>;
    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) -> usize;
    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()>;
}

#[derive(Default)]
pub struct CipherState<C: Cipher + Default> {
    cipher : C,
    n : u64,
    has_key : bool,
}

impl<C: Cipher + Default> CipherStateType for CipherState<C> {

    fn name(&self) -> &'static str {
        self.cipher.name()
    }

    fn set(&mut self, key: &[u8], n: u64) {
        self.cipher.set(key);
        self.n = n;
        self.has_key = true;
    }

    fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        assert!(self.has_key);
        let len = self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n = self.n.checked_add(1).unwrap();
        len
    }

    fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        assert!(self.has_key);
        let len = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n = self.n.checked_add(1).unwrap();
        len
    }

    fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) -> usize {
        self.encrypt_ad(&[0u8;0], plaintext, out)
    }

    fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        self.decrypt_ad(&[0u8;0], ciphertext, out)
    }
}

