pub const PSKLEN: usize = 32;
pub const CIPHERKEYLEN: usize = 32;
pub const TAGLEN: usize = 16;

pub const MAXHASHLEN: usize = 64;
pub const MAXBLOCKLEN: usize = 128;
pub const MAXMSGLEN: usize = 65535;

// P-256 uncompressed SEC-1 encodings are 65 bytes long, larger
// than the `MAXDHLEN` in the official Noise spec.
#[cfg(feature = "p256")]
pub const MAXDHLEN: usize = 65;
// Curve448 keys are the largest in the official Noise spec.
#[cfg(not(feature = "p256"))]
pub const MAXDHLEN: usize = 56;

#[cfg(feature = "hfs")]
pub const MAXKEMPUBLEN: usize = 4096;
#[cfg(feature = "hfs")]
pub const MAXKEMCTLEN: usize = 4096;
#[cfg(feature = "hfs")]
pub const MAXKEMSSLEN: usize = 32;
