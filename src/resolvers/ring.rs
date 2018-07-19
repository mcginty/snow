extern crate ring;

use super::CryptoResolver;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use self::ring::aead;
use self::ring::digest;
use constants::TAGLEN;
use params::{DHChoice, HashChoice, CipherChoice};
use types::{Random, Dh, Hash, Cipher};

/// A resolver that chooses [ring](https://github.com/briansmith/ring)-backed
/// primitives when available.
#[derive(Default)]
pub struct RingResolver;

#[cfg(feature = "ring")]
impl CryptoResolver for RingResolver {
    fn resolve_rng(&self) -> Option<Box<Random>> {
        None
    }

    fn resolve_dh(&self, _choice: &DHChoice) -> Option<Box<Dh>> {
        None
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<Hash>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(HashSHA256::default())),
            HashChoice::SHA512 => Some(Box::new(HashSHA512::default())),
            _                  => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<Cipher>> {
        match *choice {
            CipherChoice::AESGCM     => Some(Box::new(CipherAESGCM::default())),
            CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPoly::default())),
        }
    }
}

pub(crate) struct CipherAESGCM {
    sealing: aead::SealingKey,
    opening: aead::OpeningKey,
}

impl Default for CipherAESGCM {
    fn default() -> Self {
        CipherAESGCM {
            sealing: aead::SealingKey::new(&aead::AES_256_GCM, &[0u8; 32]).unwrap(),
            opening: aead::OpeningKey::new(&aead::AES_256_GCM, &[0u8; 32]).unwrap(),
        }
    }
}

impl Cipher for CipherAESGCM {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn set(&mut self, key: &[u8]) {
        self.sealing = aead::SealingKey::new(&aead::AES_256_GCM, key).unwrap();
        self.opening = aead::OpeningKey::new(&aead::AES_256_GCM, key).unwrap();
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        out[..plaintext.len()].copy_from_slice(plaintext);

        aead::seal_in_place(&self.sealing, &nonce_bytes, authtext, &mut out[..plaintext.len()+TAGLEN], 16).unwrap();
        plaintext.len() + TAGLEN
    }

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        if out.len() >= ciphertext.len() {
            let in_out = &mut out[..ciphertext.len()];
            in_out.copy_from_slice(ciphertext);

            let len = aead::open_in_place(&self.opening, &nonce_bytes, authtext, 0, in_out).map_err(|_| ())?
                .len();

            Ok(len)
        } else {
            let mut in_out = ciphertext.to_vec();

            let out0 = aead::open_in_place(&self.opening, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;
            out[..out0.len()].copy_from_slice(out0);
            Ok(out0.len())
        }
    }
}

pub(crate) struct CipherChaChaPoly {
    sealing: aead::SealingKey,
    opening: aead::OpeningKey,
}

impl Default for CipherChaChaPoly {
    fn default() -> Self {
        Self {
            sealing: aead::SealingKey::new(&aead::CHACHA20_POLY1305, &[0u8; 32]).unwrap(),
            opening: aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &[0u8; 32]).unwrap(),
        }
    }
}

impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        self.sealing = aead::SealingKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
        self.opening = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        out[..plaintext.len()].copy_from_slice(plaintext);

        aead::seal_in_place(&self.sealing, &nonce_bytes, authtext, &mut out[..plaintext.len()+TAGLEN], 16).unwrap();
        plaintext.len() + TAGLEN
    }

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        if out.len() >= ciphertext.len() {
            let in_out = &mut out[..ciphertext.len()];
            in_out.copy_from_slice(ciphertext);

            let len = aead::open_in_place(&self.opening, &nonce_bytes, authtext, 0, in_out).map_err(|_| ())?
                .len();

            Ok(len)
        } else {
            let mut in_out = ciphertext.to_vec();

            let out0 = aead::open_in_place(&self.opening, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;
            out[..out0.len()].copy_from_slice(out0);
            Ok(out0.len())
        }
    }
}
pub(crate) struct HashSHA256 {
    context: digest::Context,
}

impl Default for HashSHA256 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA256) }
    }
}

impl Hash for HashSHA256 {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA256);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..32].copy_from_slice(self.context.clone().finish().as_ref());
    }
}

pub(crate) struct HashSHA512 {
    context: digest::Context,
}

impl Default for HashSHA512 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA512) }
    }
}

impl Hash for HashSHA512 {
    fn name(&self) -> &'static str {
        "SHA512"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA512);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..64].copy_from_slice(self.context.clone().finish().as_ref());
    }
}


