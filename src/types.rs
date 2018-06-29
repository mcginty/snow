//! The traits for cryptographic implementations that can be used by Noise.

use utils::copy_memory;
use constants::{MAXBLOCKLEN, MAXHASHLEN};

/// Provides randomness
pub trait Random {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

/// Provides Diffie-Hellman operations
pub trait Dh {
    fn name(&self) -> &'static str;
    fn pub_len(&self) -> usize;
    fn priv_len(&self) -> usize;

    fn set(&mut self, privkey: &[u8]);
    fn generate(&mut self, rng: &mut Random);
    fn pubkey(&self) -> &[u8];
    fn privkey(&self) -> &[u8];

    #[must_use]
    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), ()>;
}

/// Provides cipher operations
pub trait Cipher {
    fn name(&self) -> &'static str;

    fn set(&mut self, key: &[u8]);
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize;

    #[must_use]
    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()>;
}

/// Provides hashing operations
pub trait Hash {
    fn name(&self) -> &'static str;
    fn block_len(&self) -> usize;
    fn hash_len(&self) -> usize;

    /* These functions operate on internal state:
     * call reset(), then input() repeatedly, then get result() */
    fn reset(&mut self);
    fn input(&mut self, data: &[u8]);
    fn result(&mut self, out: &mut [u8]);

    /* The hmac and hkdf functions modify internal state
     * but ignore previous state, they're one-shot, static-like functions */
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= self.block_len());
        let block_len = self.block_len();
        let hash_len = self.hash_len();
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

    fn hkdf(&mut self, chaining_key: &[u8], input_key_material: &[u8], outputs: usize, out1: &mut [u8], out2: &mut [u8], out3: &mut [u8]) {
        let hash_len = self.hash_len();
        let mut temp_key = [0u8; MAXHASHLEN];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1u8], out1);
        if outputs == 1 {
            return;
        }

        let mut in2 = [0u8; MAXHASHLEN+1];
        copy_memory(&out1[0..hash_len], &mut in2);
        in2[hash_len] = 2;
        self.hmac(&temp_key, &in2[..hash_len+1], out2);
        if outputs == 2 {
            return;
        }

        let mut in3 = [0u8; MAXHASHLEN+1];
        copy_memory(&out2[0..hash_len], &mut in3);
        in3[hash_len] = 3;
        self.hmac(&temp_key, &in3[..hash_len+1], out3);
    }
}
