//! The wrappers around the default collection of cryptography and entropy providers.

#[cfg(feature = "default-resolver")]   pub mod default;
#[cfg(feature = "hacl-star-resolver")] pub mod hacl_star;
#[cfg(feature = "ring-resolver")]      pub mod ring;

use params::{CipherChoice, DHChoice, HashChoice};
use types::{Cipher, Dh, Hash, Random};

/// An object that resolves the providers of Noise crypto choices
pub trait CryptoResolver {
    fn resolve_rng(&self) -> Option<Box<Random>>;
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<Dh>>;
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<Hash>>;
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<Cipher>>;
}

pub struct FallbackResolver {
    preferred: Box<CryptoResolver>,
    fallback: Box<CryptoResolver>,
}

impl FallbackResolver {
    pub fn new(preferred: Box<CryptoResolver>, fallback: Box<CryptoResolver>) -> Self {
        Self { preferred, fallback }
    }
}

impl CryptoResolver for FallbackResolver {
    fn resolve_rng(&self) -> Option<Box<Random>> {
        self.preferred.resolve_rng().or_else(|| self.fallback.resolve_rng())
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<Dh>> {
        self.preferred.resolve_dh(choice).or_else(|| self.fallback.resolve_dh(choice))
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<Hash>> {
        self.preferred.resolve_hash(choice).or_else(|| self.fallback.resolve_hash(choice))
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<Cipher>> {
        self.preferred.resolve_cipher(choice).or_else(|| self.fallback.resolve_cipher(choice))
    }
}
