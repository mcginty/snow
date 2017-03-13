/// All error types produced by a Noise operation.
#[derive(Debug)]
pub enum NoiseError {
    /// An issue in initialization that is independent of a missing prerequisite parameter
    InitError(&'static str),

    /// A missing or otherwise malformed prerequisite during initialization
    PrereqError(String),

    /// Bad input during an operation. Typically a message that causes max message size
    /// to be exceeded.
    InputError(&'static str),

    /// Unsupported operation for the current state in the state machine.
    StateError(&'static str),

    /// Decryption error, usually due to incorrect key material.
    DecryptError
}

