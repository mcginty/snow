/// All error types produced by a Noise operation.
#[derive(Debug)]
pub enum NoiseError {
    InitError(&'static str),
    PrereqError(String),
    InputError(&'static str),
    StateError(&'static str),
    DecryptError
}

