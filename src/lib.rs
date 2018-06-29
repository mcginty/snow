//! The `snow` crate is a straightforward, Hard To Fuck Up™ Noise Protocol implementation.
//!
//! Read the [Noise Protocol Framework Spec](http://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use `NoiseBuilder` to construct a `Session`, which is main
//! state machine you will want to interact with.
//!
//! # Examples
//! See `examples/simple.rs` for a more complete TCP client/server example.
//!
//! ```rust,ignore
//! let noise = NoiseBuilder::new("Noise_NN_ChaChaPoly_BLAKE2s".parse().unwrap())
//!                          .build_initiator()
//!                          .unwrap();
//!
//! let mut buf = [0u8; 65535];
//!
//! // write first handshake message
//! noise.write_message(&[], &mut buf).unwrap();
//!
//! // receive response message
//! let incoming = receive_message_from_the_mysterious_ether();
//! noise.read_message(&incoming, &mut buf).unwrap();
//!
//! // complete handshake, and transition the state machine into transport mode
//! let noise = noise.into_transport_mode();
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
mod constants;
mod utils;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod noise;
mod session;
mod transportstate;

pub mod params;
pub mod types;
pub mod resolvers;

pub use error::*;
pub use resolvers::{CryptoResolver, FallbackResolver};
pub use noise::NoiseBuilder;
pub use session::Session;

#[cfg(feature = "default-resolver")]   pub use resolvers::default::DefaultResolver;
#[cfg(feature = "ring-resolver")]      pub use resolvers::ring::RingResolver;
#[cfg(feature = "hacl-star-resolver")] pub use resolvers::hacl_star::HaclStarResolver;
