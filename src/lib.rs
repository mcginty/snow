//! The `snow` crate is a straightforward, Hard To Fuck Up™ Noise Protocol implementation.
//!
//! Read the [Noise Protocol Framework Spec](http://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use `NoiseBuilder` to construct a`NoiseSession<HandshakeState>`,
//! which can transition to a `NoiseSession<TransportState>` once the handshake is completed.
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
//! noise.write_message(&[0u8; 0], &mut buf).unwrap();
//!
//! // receive response message
//! let incoming = receive_message_from_the_mysterious_ether();
//! noise.read_message(&incoming, &mut buf).unwrap();
//!
//! // complete handshake, and transition the state machine into transport mode
//! let noise = noise.into_transport_mode();
//!
//! ```

#![feature(try_from)]
#[macro_use] extern crate static_slice;
mod error;
mod crypto_types;
mod wrappers;
mod constants;
mod utils;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod noise;
mod session;
mod transportstate;

pub mod params;

pub use crypto_types::{Random, Dh, Cipher, Hash};
pub use error::NoiseError;
pub use handshakestate::HandshakeState;
pub use cipherstate::CipherStateType;
pub use noise::NoiseBuilder;
pub use session::*;
pub use transportstate::*;
