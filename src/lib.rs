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
//! # Crypto
//!
//! Cryptographic providers are swappable through `Builder::with_resolver()`, but by default
//! it chooses select, artisanal pure-Rust implementations (see `Cargo.toml` for a quick
//! overview).
//!
//! ### Other Providers
//!
//! #### ring
//!
//! [ring](https://github.com/briansmith/ring) is a crypto library based off of BoringSSL
//! and is significantly faster than most of the pure-Rust implementations.
//!
//! If you enable the `ring-resolver` feature, Snow will include a `resolvers::ring` module
//! as well as a `RingAcceleratedResolver` available to be used with
//! `Builder::with_resolver()`.
//!
//! If you enable the `ring-accelerated` feature, Snow will default to choosing `ring`'s
//! crypto implementations when available.
//!
//! ### Resolver primitives supported
//!
//! |                          | default          | ring               |
//! | -----------------------: | :--------------: | :----------------: |
//! |     CSPRNG               | ✔️               | ✔️                 |
//! |      25519               | ✔️               | ✔️                 |
//! |        448               |                  |                    |
//! |      P-256<sup>🏁</sup>  | ✔️               |                    |
//! |     AESGCM               | ✔️               | ✔️                 |
//! | ChaChaPoly               | ✔️               | ✔️                 |
//! | XChaChaPoly<sup>🏁</sup> | ✔️               |                    |
//! |     SHA256               | ✔️               | ✔️                 |
//! |     SHA512               | ✔️               | ✔️                 |
//! |    BLAKE2s               | ✔️               |                    |
//! |    BLAKE2b               | ✔️               |                    |
//!
//! 🏁 P-256 and XChaChaPoly are not in the official specification of Noise, and thus need to be enabled
//! via the feature flags `use-p256` and `use-xchacha20poly1305`, respectively.
//!
//! ## `no_std` support and feature selection
//!
//! Snow can be used in `no_std` environments if `alloc` is provided.
//!
//! By default, Snow uses the standard library, default crypto resolver and a selected collection
//! of crypto primitives. To use Snow in `no_std` environments or make other kinds of customized
//! setups, use Snow with `default-features = false`. This way you will individually select
//! the components you wish to use. `default-resolver` is the only built-in resolver that
//! currently supports `no_std`.
//!
//! To use a custom setup with `default-resolver`, enable your desired selection of cryptographic primitives:
//!
//! |             | Primitive                  | Feature flag           |
//! | ----------: | :------------------------- | :--------------------- |
//! | **DHs**     | Curve25519                 | `use-curve25519`       |
//! |             | P-256<sup>:🏁:</sup>       | `use-p256`             |
//! | **Ciphers** | AES-GCM                    | `use-aes-gcm`          |
//! |             | ChaChaPoly                 | `use-chacha20poly1305` |
//! |             | XChaChaPoly<sup>:🏁:</sup> | `use-xchacha20poly1305`|
//! | **Hashes**  | SHA-256                    | `use-sha2`             |
//! |             | SHA-512                    | `use-sha2`             |
//! |             | BLAKE2s                    | `use-blake2`           |
//! |             | BLAKE2b                    | `use-blake2`           |
//!
//! 🏁 XChaChaPoly and P-256 are not in the official specification of Noise, but they are supported
//! by Snow.

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
        // `default-resolver` and `ring-resolver` may be enabled at the same time
        // when using the `ring-accelerated` feature. _ring_ provides AES-GCM and
        // ChaChaPoly-1305 too, which are the only two required ciphers.
        feature = "ring-resolver",
        feature = "use-xchacha20poly1305"
    )),
    // See above rationale; _ring_ provides SHA2 at minimum which is a supported config.
    not(any(feature = "use-sha2", feature = "use-blake2", feature = "ring-resolver"))
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
