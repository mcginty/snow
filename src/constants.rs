
pub const CIPHERKEYLEN : usize = 32;
pub const TAGLEN : usize = 16;

/* TODO: replace with associated constants once that Rust feature is stable */
pub const MAXHASHLEN : usize = 64;
pub const MAXBLOCKLEN : usize = 128;
pub const DHLEN : usize = 32; /* TODO: generalize for Curve448, but annoying without prev item */
