
pub const CIPHERKEYLEN : usize = 32;
pub const TAGLEN : usize = 16;

/* TODO: replace with associated constants once that Rust feature is stable */
pub const MAXHASHLEN : usize = 64;
pub const MAXBLOCKLEN : usize = 128;
pub const DHLEN : usize = 32; /* TODO: generalize for Curve448, but annoying without prev item */

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}

pub trait RandomType {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

pub trait DhType {
    fn name(&self, out: &mut [u8]) -> usize;

    fn clear(&mut self);
    fn is_empty(&self) -> bool;
    fn set(&mut self, privkey: &[u8], pubkey: &[u8]);
    fn generate(&mut self, rng: &mut RandomType); 
    fn pubkey(&self) -> &[u8];
    fn dh(&self, pubkey: &[u8]) -> [u8; DHLEN];
}

pub trait CipherType {
    fn name(&self, out: &mut [u8]) -> usize;

    fn clear(&mut self);
    fn set(&mut self, key: &[u8]);
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
}

pub trait HashType {
    fn name(&self, out: &mut [u8]) -> usize;
    fn block_len(&self) -> usize; /* see TODO at top */
    fn hash_len(&self) -> usize; /* see TODO at top */

    fn reset(&mut self);
    fn input(&mut self, data: &[u8]);
    fn result(&mut self, out: &mut [u8]);

    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= self.block_len());
        let block_len = self.block_len();
        let hash_len = self.block_len();
        let mut ipad = [0x36u8; MAXBLOCKLEN];
        let mut opad = [0x5cu8; MAXBLOCKLEN];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }
        self.reset();
        self.input(&ipad[..block_len]);
        self.input(data);
        let mut inner_output = [0u8; MAXHASHLEN];
        self.result(&mut inner_output);
        self.reset();
        self.input(&opad[..block_len]);
        self.input(&inner_output[..hash_len]);
        self.result(out);
    }

    fn hkdf(&mut self, chaining_key: &[u8], input_key_material: &[u8], out1: &mut [u8], out2: & mut[u8]) {
        let hash_len = self.block_len();
        let mut temp_key = [0u8; MAXHASHLEN];
        let mut in2 = [0u8; MAXHASHLEN+1];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1u8], out1);
        copy_memory(&out1[0..hash_len], &mut in2);
        in2[self.hash_len()] = 2;
        self.hmac(&temp_key, &in2[..hash_len+1], out2);
    }
}

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
    pub n : u64,
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

