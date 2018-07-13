//! The `snow` crate is a straightforward, Hard To Fuck Up™ Noise Protocol implementation.
//!
//! Read the [Noise Protocol Framework Spec](http://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use `Builder` to construct a `Session`, which is main
//! state machine you will want to interact with.
//!
//! # Examples
//! See `examples/simple.rs` for a more complete TCP client/server example.
//!
//! ```
//! # use snow::SnowError;
//! #
//! # fn try_main() -> Result<(), SnowError> {
//! let mut initiator = snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
//!     .build_initiator()?;
//! let mut responder = snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
//!     .build_responder()?;
//! 
//! let mut read_buf = [0u8; 65535];
//! let mut first_msg = [0u8; 65535];
//! let mut second_msg = [0u8; 65535];
//!
//! // initiator writes first handshake message
//! let len = initiator.write_message(&[], &mut first_msg)?;
//!
//! // responder reads the message...
//! responder.read_message(&first_msg[..len], &mut read_buf)?;
//! 
//! // responder writes second (final) handshake message
//! let len = responder.write_message(&[], &mut second_msg)?;
//! 
//! // responder reads the message...
//! initiator.read_message(&second_msg[..len], &mut read_buf)?;
//!
//! // complete handshake, and transition the state machines into transport mode
//! let initiator = initiator.into_transport_mode();
//! let responder = responder.into_transport_mode();
//! #     Ok(())
//! # }
//! #
//! # fn main() {
//! #     try_main().unwrap();
//! # }
//! ```
//! 
//! ```rust,ignore
//! let noise = snow::Builder::new("Noise_NN_ChaChaPoly_BLAKE2s".parse().unwrap())
//!     .build_initiator()
//!     .unwrap();
//!
//!
//! ```

#![cfg_attr(feature = "nightly", feature(try_from))]

#[cfg(any(feature = "default-resolver", feature = "hacl-star-resolver"))]
#[macro_use]
extern crate arrayref;

#[macro_use] extern crate static_slice;
#[macro_use] extern crate failure_derive;
extern crate byteorder;
extern crate failure;
extern crate smallvec;

#[macro_use]
mod error;
#[macro_use]
mod utils;
mod constants;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod builder;
mod session;
mod transportstate;

pub mod params;
pub mod types;
pub mod resolvers;

pub use error::{SnowError, InitStage, Prerequisite, StateProblem};
pub use resolvers::{CryptoResolver, FallbackResolver};
pub use builder::Builder;
pub use session::Session;

#[cfg(feature = "default-resolver")]   pub use resolvers::default::DefaultResolver;
#[cfg(feature = "ring-resolver")]      pub use resolvers::ring::RingResolver;
#[cfg(feature = "hacl-star-resolver")] pub use resolvers::hacl_star::HaclStarResolver;
