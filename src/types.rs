//! The traits for cryptographic implementations that can be used by Noise.

use crate::{constants::CIPHERKEYLEN, Error};
use rand_core::{CryptoRng, RngCore};

/// CSPRNG operations
pub trait Random: CryptoRng + RngCore + Send + Sync {}

/// Diffie-Hellman operations
pub trait Dh: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// The length in bytes of a public key for this primitive
    fn pub_len(&self) -> usize;

    /// The length in bytes of a private key for this primitive
    fn priv_len(&self) -> usize;

    /// Set the private key
    fn set(&mut self, privkey: &[u8]);

    /// Generate a new private key
    fn generate(&mut self, rng: &mut dyn Random);

    /// Get the public key
    fn pubkey(&self) -> &[u8];

    /// Get the private key
    fn privkey(&self) -> &[u8];

    /// Calculate a Diffie-Hellman exchange.
    ///
    /// # Errors
    /// Returns `Error::Dh` in the event that the Diffie-Hellman failed.
    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error>;
}

/// Cipher operations
pub trait Cipher: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// Set the key
    fn set(&mut self, key: &[u8; CIPHERKEYLEN]);

    /// Encrypt (with associated data) a given plaintext.
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize;

    /// Decrypt (with associated data) a given ciphertext.
    ///
    /// # Errors
    /// Returns `Error::Decrypt` in the event that the decryption failed.
    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error>;
}

/// Hashing operations
pub trait Hash: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// The block length for the primitive
    fn block_len(&self) -> usize;

    /// The final hash digest length for the primitive
    fn hash_len(&self) -> usize;

    /// Reset the internal state
    fn reset(&mut self);

    /// Provide input to the internal state
    fn input(&mut self, data: &[u8]);

    /// Get the resulting hash
    fn result(&mut self, out: &mut [u8]);
}

/// Kem operations.
#[cfg(feature = "hfs")]
pub trait Kem: Send + Sync {
    /// The string that the Noise spec defines for the primitive.
    fn name(&self) -> &'static str;

    /// The length in bytes of a public key for this primitive.
    fn pub_len(&self) -> usize;

    /// The length in bytes the Kem cipherthext for this primitive.
    fn ciphertext_len(&self) -> usize;

    /// Shared secret length in bytes that this Kem encapsulates.
    fn shared_secret_len(&self) -> usize;

    /// Generate a new private key.
    fn generate(&mut self, rng: &mut dyn Random);

    /// Get the public key
    fn pubkey(&self) -> &[u8];

    /// Generate a shared secret and encapsulate it using this Kem.
    #[must_use]
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), ()>;

    /// Decapsulate a ciphertext producing a shared secret.
    #[must_use]
    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, ()>;
}
