//! The `snow` crate aims to be a straightforward Noise Protocol implementation. See the
//! [Noise Protocol Framework Spec](https://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use [`Builder`] to construct a [`HandshakeState`], where you
//! will complete the handshake phase and convert into either a [`TransportState`] (typically
//! when done over a reliable transport where the internal message counter can be used) or
//! [`StatelessTransportState`] (when you control the message counter for unreliable transports
//! like UDP).
//!
//! # Example
//!
//! ```
//! # use snow::Error;
//! #
//! # #[cfg(any(feature = "default-resolver-crypto", feature = "ring-accelerated"))]
//! # fn try_main() -> Result<(), Error> {
//! static PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
//!
//! let mut initiator = snow::Builder::new(PATTERN.parse()?)
//!     .build_initiator()?;
//! let mut responder = snow::Builder::new(PATTERN.parse()?)
//!     .build_responder()?;
//!
//! let (mut read_buf, mut first_msg, mut second_msg) =
//!     ([0u8; 1024], [0u8; 1024], [0u8; 1024]);
//!
//! // -> e
//! let len = initiator.write_message(&[], &mut first_msg)?;
//!
//! // responder processes the first message...
//! responder.read_message(&first_msg[..len], &mut read_buf)?;
//!
//! // <- e, ee
//! let len = responder.write_message(&[], &mut second_msg)?;
//!
//! // initiator processes the response...
//! initiator.read_message(&second_msg[..len], &mut read_buf)?;
//!
//! // NN handshake complete, transition into transport mode.
//! let initiator = initiator.into_transport_mode();
//! let responder = responder.into_transport_mode();
//! #     Ok(())
//! # }
//! #
//! # #[cfg(not(any(feature = "default-resolver-crypto", feature = "ring-accelerated")))]
//! # fn try_main() -> Result<(), ()> { Ok(()) }
//! #
//! # fn main() {
//! #     try_main().unwrap();
//! # }
//! ```
//!
//! See `examples/simple.rs` for a more complete TCP client/server example with static keys.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Make sure the user is running a supported configuration.
#[cfg(feature = "default-resolver")]
#[cfg(any(
    not(any(feature = "use-curve25519")),
    not(any(
        feature = "use-aes-gcm",
        feature = "use-chacha20poly1305",
        feature = "use-xchacha20poly1305"
    )),
    not(any(feature = "use-sha2", feature = "use-blake2"))
))]
compile_error!(
    "Valid selection of crypto primitived must be enabled when using feature 'default-resolver'.
    Enable at least one DH feature, one Cipher feature and one Hash feature. Check README.md for details."
);

macro_rules! copy_slices {
    ($inslice:expr, $outslice:expr) => {
        $outslice[..$inslice.len()].copy_from_slice(&$inslice[..])
    };
}

macro_rules! static_slice {
    ($_type:ty: $($item:expr),*) => ({
        static STATIC_SLICE: &'static [$_type] = &[$($item),*];
        STATIC_SLICE
    });
}

mod builder;
mod cipherstate;
mod constants;
pub mod error;
mod handshakestate;
mod stateless_transportstate;
mod symmetricstate;
mod transportstate;
mod utils;

pub mod params;
pub mod resolvers;
pub mod types;

pub use crate::{
    builder::{Builder, Keypair},
    error::Error,
    handshakestate::HandshakeState,
    stateless_transportstate::StatelessTransportState,
    transportstate::TransportState,
};
