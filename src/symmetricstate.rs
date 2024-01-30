use crate::{
    cipherstate::CipherState,
    constants::{CIPHERKEYLEN, MAXBLOCKLEN, MAXHASHLEN},
    error::Error,
    types::Hash,
};

#[derive(Copy, Clone)]
pub(crate) struct SymmetricStateData {
    h:       [u8; MAXHASHLEN],
    ck:      [u8; MAXHASHLEN],
    has_key: bool,
}

impl Default for SymmetricStateData {
    fn default() -> Self {
        SymmetricStateData {
            h:       [0_u8; MAXHASHLEN],
            ck:      [0_u8; MAXHASHLEN],
            has_key: false,
        }
    }
}

pub(crate) struct SymmetricState {
    cipherstate: CipherState,
    hasher:      Box<dyn Hash>,
    inner:       SymmetricStateData,
}

impl SymmetricState {
    pub fn new(cipherstate: CipherState, hasher: Box<dyn Hash>) -> SymmetricState {
        SymmetricState { cipherstate, hasher, inner: SymmetricStateData::default() }
    }

    pub fn initialize(&mut self, handshake_name: &str) {
        if handshake_name.len() <= self.hasher.hash_len() {
            copy_slices!(handshake_name.as_bytes(), self.inner.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name.as_bytes());
            self.hasher.result(&mut self.inner.h);
        }
        copy_slices!(self.inner.h, &mut self.inner.ck);
        self.inner.has_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]);
        hkdf(
            &mut self.hasher,
            &self.inner.ck[..hash_len],
            data,
            2,
            &mut hkdf_output.0,
            &mut hkdf_output.1,
            &mut [],
        );

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_key = [0_u8; CIPHERKEYLEN];
        cipher_key.copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);

        self.inner.ck = hkdf_output.0;
        self.cipherstate.set(&cipher_key, 0);
        self.inner.has_key = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.inner.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.inner.h);
    }

    pub fn mix_key_and_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]);
        hkdf(
            &mut self.hasher,
            &self.inner.ck[..hash_len],
            data,
            3,
            &mut hkdf_output.0,
            &mut hkdf_output.1,
            &mut hkdf_output.2,
        );
        self.inner.ck = hkdf_output.0;
        self.mix_hash(&hkdf_output.1[..hash_len]);

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_key = [0_u8; CIPHERKEYLEN];
        cipher_key.copy_from_slice(&hkdf_output.2[..CIPHERKEYLEN]);
        self.cipherstate.set(&cipher_key, 0);
    }

    pub fn has_key(&self) -> bool {
        self.inner.has_key
    }

    /// Encrypt a message and mixes in the hash of the output
    pub fn encrypt_and_mix_hash(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let hash_len = self.hasher.hash_len();
        let output_len = if self.inner.has_key {
            self.cipherstate.encrypt_ad(&self.inner.h[..hash_len], plaintext, out)?
        } else {
            copy_slices!(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        Ok(output_len)
    }

    pub fn decrypt_and_mix_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.inner.has_key {
            self.cipherstate.decrypt_ad(&self.inner.h[..hash_len], data, out)?
        } else {
            if out.len() < data.len() {
                return Err(Error::Decrypt);
            }
            copy_slices!(data, out);
            data.len()
        };
        self.mix_hash(data);
        Ok(payload_len)
    }

    pub fn split(&mut self, child1: &mut CipherState, child2: &mut CipherState) {
        let mut hkdf_output = ([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]);
        self.split_raw(&mut hkdf_output.0, &mut hkdf_output.1);

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_keys = ([0_u8; CIPHERKEYLEN], [0_u8; CIPHERKEYLEN]);
        cipher_keys.0.copy_from_slice(&hkdf_output.0[..CIPHERKEYLEN]);
        cipher_keys.1.copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);
        child1.set(&cipher_keys.0, 0);
        child2.set(&cipher_keys.1, 0);
    }

    pub fn split_raw(&mut self, out1: &mut [u8], out2: &mut [u8]) {
        let hash_len = self.hasher.hash_len();
        hkdf(&mut self.hasher, &self.inner.ck[..hash_len], &[0_u8; 0], 2, out1, out2, &mut []);
    }

    pub(crate) fn checkpoint(&mut self) -> SymmetricStateData {
        self.inner
    }

    pub(crate) fn restore(&mut self, checkpoint: SymmetricStateData) {
        self.inner = checkpoint;
    }

    pub fn handshake_hash(&self) -> &[u8] {
        let hash_len = self.hasher.hash_len();
        &self.inner.h[..hash_len]
    }
}

/// Calculate HMAC, as specified in the Noise spec.
///
/// NOTE: This method clobbers the existing internal state
pub(crate) fn hmac(hasher: &mut Box<dyn Hash>, key: &[u8], data: &[u8], out: &mut [u8]) {
    let key_len = key.len();
    let block_len = hasher.block_len();
    let hash_len = hasher.hash_len();
    assert!(key.len() <= block_len, "key and block lengths differ");
    let mut ipad = [0x36_u8; MAXBLOCKLEN];
    let mut opad = [0x5c_u8; MAXBLOCKLEN];
    for count in 0..key_len {
        ipad[count] ^= key[count];
        opad[count] ^= key[count];
    }
    hasher.reset();
    hasher.input(&ipad[..block_len]);
    hasher.input(data);
    let mut inner_output = [0_u8; MAXHASHLEN];
    hasher.result(&mut inner_output);
    hasher.reset();
    hasher.input(&opad[..block_len]);
    hasher.input(&inner_output[..hash_len]);
    hasher.result(out);
}

/// Derive keys as specified in the Noise spec.
///
/// NOTE: This method clobbers the existing internal state
pub(crate) fn hkdf(
    hasher: &mut Box<dyn Hash>,
    chaining_key: &[u8],
    input_key_material: &[u8],
    outputs: usize,
    out1: &mut [u8],
    out2: &mut [u8],
    out3: &mut [u8],
) {
    let hash_len = hasher.hash_len();
    let mut temp_key = [0_u8; MAXHASHLEN];
    hmac(hasher, chaining_key, input_key_material, &mut temp_key);
    hmac(hasher, &temp_key, &[1_u8], out1);
    if outputs == 1 {
        return;
    }

    let mut in2 = [0_u8; MAXHASHLEN + 1];
    copy_slices!(out1[0..hash_len], &mut in2);
    in2[hash_len] = 2;
    hmac(hasher, &temp_key, &in2[..=hash_len], out2);
    if outputs == 2 {
        return;
    }

    let mut in3 = [0_u8; MAXHASHLEN + 1];
    copy_slices!(out2[0..hash_len], &mut in3);
    in3[hash_len] = 3;
    hmac(hasher, &temp_key, &in3[..=hash_len], out3);
}
