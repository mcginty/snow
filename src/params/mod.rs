#![allow(clippy::match_on_vec_items)]
#![allow(clippy::enum_glob_use)]

//! All structures related to Noise parameter definitions (cryptographic primitive choices, protocol
//! patterns/names)

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String};

use crate::error::{Error, PatternProblem};
use core::str::FromStr;
mod patterns;

pub use self::patterns::{
    HandshakeChoice, HandshakeModifier, HandshakeModifierList, HandshakePattern,
    SUPPORTED_HANDSHAKE_PATTERNS,
};

pub(crate) use self::patterns::{DhToken, HandshakeTokens, MessagePatterns, Token};

/// I recommend you choose `Noise`.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum BaseChoice {
    /// Ole' faithful.
    Noise,
}

impl FromStr for BaseChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::BaseChoice::*;
        match s {
            "Noise" => Ok(Noise),
            _ => Err(PatternProblem::UnsupportedBaseType.into()),
        }
    }
}

/// Which Diffie-Hellman primitive to use. One of `25519` or `448`, per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DHChoice {
    /// The Curve25519 elliptic curve.
    Curve25519,
    /// The Curve448 elliptic curve.
    Curve448,
    #[cfg(feature = "p256")]
    /// The P-256 elliptic curve.
    P256,
}

impl FromStr for DHChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::DHChoice::*;
        match s {
            "25519" => Ok(Curve25519),
            "448" => Ok(Curve448),
            #[cfg(feature = "p256")]
            "P256" => Ok(P256),
            _ => Err(PatternProblem::UnsupportedDhType.into()),
        }
    }
}

/// One of `ChaChaPoly` or `AESGCM`, per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum CipherChoice {
    /// The ChaCha20Poly1305 AEAD.
    ChaChaPoly,
    #[cfg(feature = "use-xchacha20poly1305")]
    /// The XChaCha20Poly1305 AEAD, an extended nonce variant of ChaCha20Poly1305.
    /// This variant is hidden behind a feature flag to highlight that it is not in the
    /// official specification of the Noise Protocol.
    XChaChaPoly,
    /// The AES-GCM AEAD.
    AESGCM,
}

impl FromStr for CipherChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::CipherChoice::*;
        match s {
            "ChaChaPoly" => Ok(ChaChaPoly),
            #[cfg(feature = "use-xchacha20poly1305")]
            "XChaChaPoly" => Ok(XChaChaPoly),
            "AESGCM" => Ok(AESGCM),
            _ => Err(PatternProblem::UnsupportedCipherType.into()),
        }
    }
}

/// One of the supported SHA-family or BLAKE-family hash choices, per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HashChoice {
    /// The SHA-256 hash function.
    SHA256,
    /// The SHA-512 hash function.
    SHA512,
    /// The BLAKE2s hash function, designed to be more efficient on 8-bit to 32-bit
    /// architectures.
    Blake2s,
    /// The BLAKE2b hash function, designed to be more efficient on 64-bit architectures.
    Blake2b,
}

impl FromStr for HashChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::HashChoice::*;
        match s {
            "SHA256" => Ok(SHA256),
            "SHA512" => Ok(SHA512),
            "BLAKE2s" => Ok(Blake2s),
            "BLAKE2b" => Ok(Blake2b),
            _ => Err(PatternProblem::UnsupportedHashType.into()),
        }
    }
}

/// One of the supported Kems provided for unstable HFS extension.
#[cfg(feature = "hfs")]
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum KemChoice {
    /// The 1024-bit Kyber variant.
    Kyber1024,
}

#[cfg(feature = "hfs")]
impl FromStr for KemChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::KemChoice::*;
        match s {
            "Kyber1024" => Ok(Kyber1024),
            _ => Err(PatternProblem::UnsupportedKemType.into()),
        }
    }
}

/// The set of choices (as specified in the Noise spec) that constitute a full protocol definition.
///
/// See: [Chapter 8: Protocol names and modifiers](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers).
///
/// # Examples
///
/// From a string definition:
///
/// ```
/// # use snow::params::*;
///
/// let params: NoiseParams = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
/// ```
#[derive(PartialEq, Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct NoiseParams {
    /// The full pattern string.
    pub name:      String,
    /// In this case, always `Noise`.
    pub base:      BaseChoice,
    /// The pattern's handshake choice (e.g. `XX`).
    pub handshake: HandshakeChoice,
    /// The pattern's DH choice (e.g. `25519`).
    pub dh:        DHChoice,
    #[cfg(feature = "hfs")]
    /// The pattern's KEM choice (e.g. `Kyber1024`).
    pub kem:       Option<KemChoice>,
    /// The pattern's cipher choice (e.g. `AESGCM`).
    pub cipher:    CipherChoice,
    /// The pattern's hash choice (e.g. `SHA256`).
    pub hash:      HashChoice,
}

impl NoiseParams {
    #[cfg(not(feature = "hfs"))]
    /// Construct a new `NoiseParams` via specifying enums directly.
    #[must_use]
    pub fn new(
        name: String,
        base: BaseChoice,
        handshake: HandshakeChoice,
        dh: DHChoice,
        cipher: CipherChoice,
        hash: HashChoice,
    ) -> Self {
        NoiseParams { name, base, handshake, dh, cipher, hash }
    }

    #[cfg(feature = "hfs")]
    /// Construct a new NoiseParams via specifying enums directly.
    #[must_use] pub fn new(
        name: String,
        base: BaseChoice,
        handshake: HandshakeChoice,
        dh: DHChoice,
        kem: Option<KemChoice>,
        cipher: CipherChoice,
        hash: HashChoice,
    ) -> Self {
        NoiseParams { name, base, handshake, dh, kem, cipher, hash }
    }
}

impl FromStr for NoiseParams {
    type Err = Error;

    #[cfg(not(feature = "hfs"))]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('_');
        let params = NoiseParams::new(
            s.to_owned(),
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
        );
        if split.next().is_some() {
            return Err(PatternProblem::TooManyParameters.into());
        }
        Ok(params)
    }

    #[cfg(feature = "hfs")]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('_').peekable();
        let p = NoiseParams::new(
            s.to_owned(),
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split
                .peek()
                .ok_or(PatternProblem::TooFewParameters)?.split('+')
                .nth(0)
                .ok_or(PatternProblem::TooFewParameters)?
                .parse()?,
            split
                .next()
                .ok_or(PatternProblem::TooFewParameters)?.split_once('+').map(|x| x.1)
                .map(str::parse)
                .transpose()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
            split.next().ok_or(PatternProblem::TooFewParameters)?.parse()?,
        );
        if split.next().is_some() {
            return Err(PatternProblem::TooManyParameters.into());
        }

        // Validate that a KEM is specified iff the hfs modifier is present
        if p.handshake.is_hfs() != p.kem.is_some() {
            return Err(PatternProblem::TooFewParameters.into());
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

    #[test]
    fn test_simple_handshake() {
        let _: HandshakePattern = "XX".parse().unwrap();
    }

    #[test]
    fn test_basic() {
        let p: NoiseParams = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
        assert!(p.handshake.modifiers.list.is_empty());
    }

    #[test]
    #[cfg(feature = "p256")]
    fn test_p256() {
        let p: NoiseParams = "Noise_XX_P256_AESGCM_SHA256".parse().unwrap();
        assert_eq!(p.dh, DHChoice::P256);
    }

    #[test]
    fn test_basic_deferred() {
        let p: NoiseParams = "Noise_X1X1_25519_AESGCM_SHA256".parse().unwrap();
        assert!(p.handshake.modifiers.list.is_empty());
    }

    #[test]
    fn test_fallback_mod() {
        let p: NoiseParams = "Noise_XXfallback_25519_AESGCM_SHA256".parse().unwrap();
        assert!(p.handshake.modifiers.list[0] == HandshakeModifier::Fallback);
    }

    #[test]
    fn test_psk_fallback_mod() {
        let p: NoiseParams = "Noise_XXfallback+psk0_25519_AESGCM_SHA256".parse().unwrap();
        assert!(p.handshake.modifiers.list.len() == 2);
    }

    #[test]
    fn test_single_psk_mod() {
        let p: NoiseParams = "Noise_XXpsk0_25519_AESGCM_SHA256".parse().unwrap();
        match p.handshake.modifiers.list[0] {
            HandshakeModifier::Psk(0) => {},
            _ => panic!("modifier isn't as expected!"),
        }
    }

    #[test]
    fn test_multi_psk_mod() {
        use self::HandshakeModifier::*;

        let p: NoiseParams = "Noise_XXpsk0+psk1+psk2_25519_AESGCM_SHA256".parse().unwrap();
        let mods = p.handshake.modifiers.list;
        match (mods[0], mods[1], mods[2]) {
            (Psk(0), Psk(1), Psk(2)) => {},
            _ => panic!("modifiers weren't as expected! actual: {mods:?}"),
        }
    }

    #[test]
    fn test_duplicate_psk_mod() {
        assert!("Noise_XXfallback+psk1_25519_AESGCM_SHA256".parse::<NoiseParams>().is_ok());
        assert_eq!(
            Error::Pattern(PatternProblem::DuplicateModifier),
            "Noise_XXfallback+fallback_25519_AESGCM_SHA256".parse::<NoiseParams>().unwrap_err()
        );
        assert_eq!(
            Error::Pattern(PatternProblem::DuplicateModifier),
            "Noise_XXpsk1+psk1_25519_AESGCM_SHA256".parse::<NoiseParams>().unwrap_err()
        );
    }

    #[test]
    fn test_modified_psk_handshake() {
        let p: NoiseParams = "Noise_XXpsk0_25519_AESGCM_SHA256".parse().unwrap();
        let tokens = HandshakeTokens::try_from(&p.handshake).unwrap();
        match tokens.msg_patterns[0][0] {
            Token::Psk(_) => {},
            _ => panic!("missing token!"),
        }
    }

    #[test]
    fn test_modified_multi_psk_handshake() {
        let p: NoiseParams = "Noise_XXpsk0+psk2_25519_AESGCM_SHA256".parse().unwrap();

        let tokens = HandshakeTokens::try_from(&p.handshake).unwrap();

        match tokens.msg_patterns[0][0] {
            Token::Psk(_) => {},
            _ => panic!("missing token!"),
        }

        let second = &tokens.msg_patterns[1];
        match second[second.len() - 1] {
            Token::Psk(_) => {},
            _ => panic!("missing token!"),
        }
    }

    #[test]
    fn test_invalid_psk_handshake() {
        let p: NoiseParams = "Noise_XXpsk9_25519_AESGCM_SHA256".parse().unwrap();

        assert_eq!(
            Error::Pattern(PatternProblem::InvalidPsk),
            HandshakeTokens::try_from(&p.handshake).unwrap_err()
        );
    }

    #[test]
    fn test_extraneous_string_data() {
        assert_eq!(
            Error::Pattern(PatternProblem::TooManyParameters),
            "Noise_XXpsk0_25519_AESGCM_SHA256_HackThePlanet".parse::<NoiseParams>().unwrap_err()
        );
    }
}
