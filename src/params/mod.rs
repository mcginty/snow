//! All structures related to Noise parameter definitions (cryptographic primitive choices, protocol
//! patterns/names)

use std::str::FromStr;
mod patterns;

pub use self::patterns::*;

/// One of "Noise" or "NoisePSK", per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum BaseChoice {
    Noise,
    NoisePSK,
}

impl FromStr for BaseChoice {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::BaseChoice::*;
        match s {
            "Noise"    => Ok(Noise),
            "NoisePSK" => Ok(NoisePSK),
            _          => Err("base type unsupported"),
        }
    }
}

/// One of "25519" or "448", per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DHChoice {
    Curve25519,
    Ed448,
}

impl FromStr for DHChoice {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::DHChoice::*;
        match s {
            "25519" => Ok(Curve25519),
            "448"   => Ok(Ed448),
            _       => Err("DH type unsupported")
        }
    }
}

/// One of "ChaChaPoly" or "AESGCM", per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum CipherChoice {
    ChaChaPoly,
    AESGCM,
}

impl FromStr for CipherChoice {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::CipherChoice::*;
        match s {
            "ChaChaPoly" => Ok(ChaChaPoly),
            "AESGCM"     => Ok(AESGCM),
            _            => Err("cipher type unsupported")
        }
    }
}

/// One of the support SHA-family or BLAKE-family hash choices, per the spec.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HashChoice {
    SHA256,
    SHA512,
    Blake2s,
    Blake2b,
}

impl FromStr for HashChoice {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::HashChoice::*;
        match s {
            "SHA256"  => Ok(SHA256),
            "SHA512"  => Ok(SHA512),
            "BLAKE2s" => Ok(Blake2s),
            "BLAKE2b" => Ok(Blake2b),
            _         => Err("hash type unsupported")
        }
    }
}

/// The set of choices (as specified in the Noise spec) that constitute a full protocol definition.
///
/// See: [Chapter 11: Protocol Names](http://noiseprotocol.org/noise.html#protocol-names).
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
///
/// Or the more verbose, but significantly less stringy:
///
/// ```
/// # use snow::params::*;
///
/// let params: NoiseParams = NoiseParams::new(BaseChoice::Noise,
///                                            HandshakePattern::XX,
///                                            DHChoice::Curve25519,
///                                            CipherChoice::AESGCM,
///                                            HashChoice::SHA256);
/// ```
#[derive(PartialEq, Clone, Copy, Debug)]
pub struct NoiseParams {
    pub base: BaseChoice,
    pub handshake: HandshakePattern,
    pub dh: DHChoice,
    pub cipher: CipherChoice,
    pub hash: HashChoice,
}

impl NoiseParams {

    /// Construct a new NoiseParams via specifying enums directly.
    pub fn new(base: BaseChoice,
               handshake: HandshakePattern,
               dh: DHChoice,
               cipher: CipherChoice,
               hash: HashChoice) -> Self
    {
        NoiseParams {
            base: base,
            handshake: handshake,
            dh: dh,
            cipher: cipher,
            hash: hash,
        }
    }
}

impl FromStr for NoiseParams {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('_');
        static TOO_FEW: &'static str = "too few parameters";
        Ok(NoiseParams::new(split.next().ok_or(TOO_FEW)?.parse()?,
                            split.next().ok_or(TOO_FEW)?.parse()?,
                            split.next().ok_or(TOO_FEW)?.parse()?,
                            split.next().ok_or(TOO_FEW)?.parse()?,
                            split.next().ok_or(TOO_FEW)?.parse()?))
    }
}
