//! All error types used by Snow operations.

error_chain!{
    errors {
        Init(stage: InitStage) {
            description("an error occurred during initialization")
            display("initialization failed at {:?} stage", stage)
        }
        Prereq(prereq: Prerequisite) {
            description("a required argument was not provided to the builder")
            display("missing prerequisite: {:?}", prereq)
        }
        State(state_problem: StateProblem) {
            description("invalid state error")
            display("state error of type {:?}", state_problem)
        }
        Input
        Decrypt
    }
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[derive(Debug)]
pub enum InitStage {
    ValidateKeyLengths,
    ValidatePskLengths,
    ValidateCipherTypes,
    GetRngImpl,
    GetDhImpl,
    GetCipherImpl,
    GetHashImpl,
}

/// A prerequisite that may be missing.
#[derive(Debug)]
pub enum Prerequisite {
    LocalPrivateKey,
    RemotePublicKey,
}

/// Specific errors in the state machine.
#[derive(Debug)]
pub enum StateProblem {
    MissingKeyMaterial,
    MissingPsk,
    NotTurnToWrite,
    NotTurnToRead,
    HandshakeNotFinished,
    HandshakeAlreadyFinished,
    OneWay,
}
