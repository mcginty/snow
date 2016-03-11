
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

pub trait Random {
    fn new() -> Self;
    fn fill_bytes(&mut self, out: &mut [u8]);
}

pub trait Dh {
    fn name(out: &mut [u8]) -> usize;
    fn new(privkey: &[u8], pubkey: &[u8]) -> Self;
    fn generate<R: Random>(rng: &mut R) -> Self; 
    
    fn pubkey(&self) -> &[u8];
    fn dh(&self, pubkey: &[u8]) -> [u8; DHLEN];
}

pub trait Cipher {
    fn name(out: &mut [u8]) -> usize;
    fn new(key: &[u8]) -> Self;

    fn encrypt(&mut self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt(&mut self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
}

pub trait Hash : Sized {
    fn name(out: &mut [u8]) -> usize;
    fn new() -> Self;

    fn block_len() -> usize; /* see TODO at top */
    fn hash_len() -> usize; /* see TODO at top */

    fn input(&mut self, data: &[u8]);
    fn result(&mut self, out: &mut [u8]);

    fn hmac(key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= Self::block_len());
        let mut ipad = [0x36u8; MAXBLOCKLEN];
        let mut opad = [0x5cu8; MAXBLOCKLEN];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }
        let mut inner_hasher = Self::new();
        inner_hasher.input(&ipad[..Self::block_len()]);
        inner_hasher.input(data);
        let mut inner_output = [0u8; MAXHASHLEN];
        inner_hasher.result(&mut inner_output);
        let mut outer_hasher = Self::new();
        outer_hasher.input(&opad[..Self::block_len()]);
        outer_hasher.input(&inner_output[..Self::hash_len()]);
        outer_hasher.result(out);
    }

    fn hkdf(chaining_key: &[u8], input_key_material: &[u8], out1: &mut [u8], out2: & mut[u8]) {
        let mut temp_key = [0u8; MAXHASHLEN];
        let mut in2 = [0u8; MAXHASHLEN+1];
        Self::hmac(chaining_key, input_key_material, &mut temp_key);
        Self::hmac(&temp_key, &[1u8], out1);
        copy_memory(&out1[0..Self::hash_len()], &mut in2);
        in2[Self::hash_len()] = 2;
        Self::hmac(&temp_key, &in2[..Self::hash_len()+1], out2);
    }
}

pub struct CipherState<C: Cipher> {
    cipher : C,
    pub n : u64,
    good : bool
}

impl<C: Cipher> CipherState<C> {

    pub fn new(key: &[u8], nonce: u64) -> CipherState<C> {
        CipherState{cipher : C::new(key), n: nonce, good : true}
    }

    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        assert!(self.good);
        self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n += 1;
    }

    pub fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(self.good);
        self.good = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n += 1;
        self.good
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) {
        assert!(self.good);
        self.cipher.encrypt(self.n, &[0u8;0], plaintext, out);
        self.n += 1;
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(self.good);
        self.good = self.cipher.decrypt(self.n, &[0u8;0], ciphertext, out);
        self.n += 1;
        self.good
    }
}

