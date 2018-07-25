//! All error types used by Snow operations.

/// Exits a function early with an error.
///
/// The `err!` macro provides an easy way to exit a function. `err!(X)` is
/// equivalent to writing:
///
/// ```rust,ignore
/// return Err(X.into())
/// ```
macro_rules! bail {
    ($e:expr) => {
        return Err(($e).into());
    };
}

/// All errors in snow will return a `SnowError` enum.
#[allow(missing_docs)]
#[derive(Fail, Debug)]
pub enum SnowError {
    #[fail(display = "pattern failed to parse: {:?}", reason)]
    Pattern { reason: PatternProblem },

    #[fail(display = "initialization failed at {:?}", reason)]
    Init { reason: InitStage },

    #[fail(display = "missing prerequisite: {:?}", reason)]
    Prereq { reason: Prerequisite },

    #[fail(display = "state error of type: {:?}", reason)]
    State { reason: StateProblem },

    #[fail(display = "invalid input")]
    Input,

    #[fail(display = "dh failed")]
    Dh,

    #[fail(display = "decryption failed")]
    Decrypt,
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum PatternProblem {
    TooFewParameters,
    UnsupportedHandshakeType,
    UnsupportedBaseType,
    UnsupportedHashType,
    UnsupportedDhType,
    UnsupportedCipherType,
    InvalidPsk,
    UnsupportedModifier,
}

impl From<PatternProblem> for SnowError {
    fn from(reason: PatternProblem) -> Self {
        SnowError::Pattern { reason }
    }
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum InitStage {
    ValidateKeyLengths,
    ValidatePskLengths,
    ValidateCipherTypes,
    GetRngImpl,
    GetDhImpl,
    GetCipherImpl,
    GetHashImpl,
    ValidatePskPosition,
}

impl From<InitStage> for SnowError {
    fn from(reason: InitStage) -> Self {
        SnowError::Init { reason }
    }
}

/// A prerequisite that may be missing.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Prerequisite {
    LocalPrivateKey,
    RemotePublicKey,
}

impl From<Prerequisite> for SnowError {
    fn from(reason: Prerequisite) -> Self {
        SnowError::Prereq { reason }
    }
}

/// Specific errors in the state machine.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum StateProblem {
    MissingKeyMaterial,
    MissingPsk,
    NotTurnToWrite,
    NotTurnToRead,
    HandshakeNotFinished,
    HandshakeAlreadyFinished,
    OneWay,
    StatelessTransportMode,
}

impl From<StateProblem> for SnowError {
    fn from(reason: StateProblem) -> Self {
        SnowError::State { reason }
    }
}