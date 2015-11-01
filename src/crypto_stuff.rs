
pub const MAXMSGLEN : usize = 65535;
pub const CIPHERKEYLEN : usize = 32;
pub const TAGLEN : usize = 16;

/* TODO: replace with associated constants once that Rust feature is stable */
pub const MAXHASHLEN : usize = 64;
pub const MAXBLOCKLEN : usize = 128;
pub const DHLEN : usize = 32; /* TODO: generalize for Curve448, but annoying without prev item */

pub fn copy_memory(data: &[u8], out: &mut [u8]) {
    for count in 0..data.len() {out[count] = data[count];}
}

pub trait Dh {
    fn new(privkey: &[u8], pubkey: &[u8]) -> Self;
    fn generate() -> Self; 
    
    fn pubkey(&self) -> &[u8];
    fn dh(&self, pubkey: &[u8]) -> [u8; DHLEN];
}

pub trait Cipher {
    fn new(key: &[u8], nonce: u64) -> Self;

    fn encrypt_and_inc(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt_and_inc(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
}

pub trait Hash : Sized {
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

