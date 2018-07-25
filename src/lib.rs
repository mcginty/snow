//! The `snow` crate is a straightforward, Hard To Fuck Up™ Noise Protocol implementation.
//!
//! Read the [Noise Protocol Framework Spec](http://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use [`Builder`] to construct a [`Session`], which is main
//! state machine you will want to interact with.
//!
//! # Examples
//! See `examples/simple.rs` for a more complete TCP client/server example with static keys.
//!
//! ```
//! # extern crate failure;
//! # extern crate snow;
//! # use failure::Error;
//! # use snow::SnowError;
//! #
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
//! # fn main() {
//! #     try_main().unwrap();
//! # }
//! ```
//!
//! [`Builder`]: struct.Builder.html
//! [`Session`]: enum.Session.html

#![warn(missing_docs)]
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
pub mod error;
#[macro_use]
mod utils;
mod constants;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod builder;
mod session;
mod transportstate;
mod stateless_transportstate;

pub mod params;
pub mod types;
pub mod resolvers;

pub use error::SnowError;
pub use builder::{Builder, Keypair};
pub use session::Session;
