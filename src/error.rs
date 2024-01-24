//! All error types used by Snow operations.

use std::fmt;

/// `snow` provides decently detailed errors, exposed as the [`Error`] enum,
/// to allow developers to react to errors in a more actionable way.
///
/// *With that said*, security vulnerabilities *can* be introduced by passing
/// along detailed failure information to an attacker. While an effort was
/// made to not make any particularly foolish choices in this regard, we strongly
/// recommend you don't dump the `Debug` output to a user, for example.
///
/// This enum is intentionally non-exhasutive to allow new error types to be
/// introduced without causing a breaking API change.
///
/// `snow` may eventually add a feature flag and enum variant to only return
/// an "unspecified" error for those who would prefer safety over observability.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The noise pattern failed to parse.
    Pattern(PatternProblem),

    /// Initialization failure, at a provided stage.
    Init(InitStage),

    /// Missing prerequisite material.
    Prereq(Prerequisite),

    /// An error in `snow`'s internal state.
    State(StateProblem),

    /// Invalid input.
    Input,

    /// Diffie-Hellman agreement failed.
    Dh,

    /// Decryption failed.
    Decrypt,

    /// Key-encapsulation failed
    #[cfg(feature = "hfs")]
    Kem,
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[derive(Debug, PartialEq)]
pub enum PatternProblem {
    /// Caused by a pattern string that is too short and malformed (e.g. `Noise_NN_25519`).
    TooFewParameters,
    /// The handshake section of the string (e.g. `XXpsk3`) isn't supported. Check for typos
    /// and necessary feature flags.
    UnsupportedHandshakeType,
    /// This was a trick choice -- an illusion. The correct answer was `Noise`.
    UnsupportedBaseType,
    /// Invalid hash type (e.g. `BLAKE2s`).
    /// Check that there are no typos and that any feature flags you might need are toggled
    UnsupportedHashType,
    /// Invalid DH type (e.g. `25519`).
    /// Check that there are no typos and that any feature flags you might need are toggled
    UnsupportedDhType,
    /// Invalid cipher type (e.g. `ChaChaPoly`).
    /// Check that there are no typos and that any feature flags you might need are toggled
    UnsupportedCipherType,
    /// The PSK position must be a number, and a pretty small one at that.
    InvalidPsk,
    /// Invalid modifier (e.g. `fallback`).
    /// Check that there are no typos and that any feature flags you might need are toggled
    UnsupportedModifier,
    #[cfg(feature = "hfs")]
    /// Invalid KEM type.
    /// Check that there are no typos and that any feature flags you might need are toggled
    UnsupportedKemType,
}

impl From<PatternProblem> for Error {
    fn from(reason: PatternProblem) -> Self {
        Error::Pattern(reason)
    }
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[derive(Debug, PartialEq)]
pub enum InitStage {
    /// Provided and received key lengths were not equal.
    ValidateKeyLengths,
    /// Provided and received preshared key lengths were not equal.
    ValidatePskLengths,
    /// Two separate cipher algorithms were initialized.
    ValidateCipherTypes,
    /// The RNG couldn't be initialized.
    GetRngImpl,
    /// The DH implementation couldn't be initialized.
    GetDhImpl,
    /// The cipher implementation couldn't be initialized.
    GetCipherImpl,
    /// The hash implementation couldn't be initialized.
    GetHashImpl,
    #[cfg(feature = "hfs")]
    /// The KEM implementation couldn't be initialized.
    GetKemImpl,
    /// The PSK position (specified in the pattern string) isn't valid for the given
    /// handshake type.
    ValidatePskPosition,
}

impl From<InitStage> for Error {
    fn from(reason: InitStage) -> Self {
        Error::Init(reason)
    }
}

/// A prerequisite that may be missing.
#[derive(Debug, PartialEq)]
pub enum Prerequisite {
    /// A local private key wasn't provided when it was needed by the selected pattern.
    LocalPrivateKey,
    /// A remote public key wasn't provided when it was needed by the selected pattern.
    RemotePublicKey,
}

impl From<Prerequisite> for Error {
    fn from(reason: Prerequisite) -> Self {
        Error::Prereq(reason)
    }
}

/// Specific errors in the state machine.
#[derive(Debug, PartialEq)]
pub enum StateProblem {
    /// Missing key material in the internal handshake state.
    MissingKeyMaterial,
    /// Preshared key missing in the internal handshake state.
    MissingPsk,
    /// You attempted to write a message when it's our turn to read.
    NotTurnToWrite,
    /// You attempted to read a message when it's our turn to write.
    NotTurnToRead,
    /// You tried to go into transport mode before the handshake was done.
    HandshakeNotFinished,
    /// You tried to continue the handshake when it was already done.
    HandshakeAlreadyFinished,
    /// You called a method that is only valid if this weren't a one-way handshake.
    OneWay,
    /// The nonce counter attempted to go higher than (2^64) - 1
    Exhausted,
}

impl From<StateProblem> for Error {
    fn from(reason: StateProblem) -> Self {
        Error::State(reason)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pattern(reason) => write!(f, "pattern error: {:?}", reason),
            Error::Init(reason) => {
                write!(f, "initialization error: {:?}", reason)
            },
            Error::Prereq(reason) => {
                write!(f, "prerequisite error: {:?}", reason)
            },
            Error::State(reason) => write!(f, "state error: {:?}", reason),
            Error::Input => write!(f, "input error"),
            Error::Dh => write!(f, "diffie-hellman error"),
            Error::Decrypt => write!(f, "decrypt error"),
            #[cfg(feature = "hfs")]
            Error::Kem => write!(f, "kem error"),
        }
    }
}

impl std::error::Error for Error {}
