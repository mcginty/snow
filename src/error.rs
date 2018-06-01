//! All error types used by Snow operations.

#[derive(Fail, Debug)]
pub enum SnowError {
    #[fail(display = "initialization failed at {:?}", reason)]
    Init { reason: InitStage },

    #[fail(display = "missing prerequisite: {:?}", reason)]
    Prereq { reason: Prerequisite },

    #[fail(display = "state error of type: {:?}", reason)]
    State { reason: StateProblem },

    #[fail(display = "invalid input")]
    Input,

    #[fail(display = "decryption failed")]
    Decrypt,
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[derive(Debug)]
pub enum InitStage {
    ValidateKeyLengths, ValidatePskLengths, ValidateCipherTypes,
    GetRngImpl, GetDhImpl, GetCipherImpl, GetHashImpl, ValidatePskPosition
}

/// A prerequisite that may be missing.
#[derive(Debug)]
pub enum Prerequisite {
    LocalPrivateKey, RemotePublicKey
}

/// Specific errors in the state machine.
#[derive(Debug)]
pub enum StateProblem {
    MissingKeyMaterial, MissingPsk, NotTurnToWrite, NotTurnToRead,
    HandshakeNotFinished, HandshakeAlreadyFinished, OneWay,
    AsyncTransportMode
}

