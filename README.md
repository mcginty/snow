# Snow

[![Crates.io](https://img.shields.io/crates/v/snow.svg)](https://crates.io/crates/snow)
[![Docs.rs](https://docs.rs/snow/badge.svg)](https://docs.rs/snow)
[![Build Status](https://travis-ci.org/mcginty/snow.svg?branch=master)](https://travis-ci.org/mcginty/snow)
[![dependency status](https://deps.rs/repo/github/mcginty/snow/status.svg)](https://deps.rs/repo/github/mcginty/snow)

![totally official snow logo](https://i.imgur.com/gFgvo49.jpg?1)

An implementation of Trevor Perrin's [Noise Protocol](https://noiseprotocol.org/) that is designed to be
Hard To Fuck Up™.

🔥 **Warning** 🔥 This library has not received any formal audit, and its API is subject to change whenever it's
prudent to or if the winds blow at the right heading.

## What's it look like?
See `examples/simple.rs` for a more complete TCP client/server example.

```rust
let mut noise = snow::Builder::new("Noise_NN_ChaChaPoly_BLAKE2s".parse()?)
                    .build_initiator()?;
 
let mut buf = [0u8; 65535];
 
// write first handshake message
noise.write_message(&[], &mut buf)?;
 
// receive response message
let incoming = receive_message_from_the_mysterious_ether();
noise.read_message(&incoming, &mut buf)?;
 
// complete handshake, and transition the state machine into transport mode
let mut noise = noise.into_transport_mode()?;
```

See the full documentation at [https://docs.rs/snow](https://docs.rs/snow).


## Implemented

Snow is currently based off of Noise revision 32.

- [x] Rekey()
- [x] `pskN` modifier
- [x] specifying PSKs after building `Session`
- [ ] `fallback` modifier

## Crypto
Cryptographic providers are swappable through `Builder::with_provider()`, but by default it chooses select, artisanal
pure-Rust implementations (see `Cargo.toml` for a quick overview).

### Providers

#### ring

[ring](https://github.com/briansmith/ring) is a crypto library based off of BoringSSL and is significantly faster than most of the pure-Rust implementations.

If you enable the `ring-resolver` feature, Snow will include a `ring_wrapper` module as well as a `RingAcceleratedResolver` available to be used with `NoiseBuilder::with_resolver()`.

If you enable the `ring-accelerated` feature, Snow will default to choosing `ring`'s crypto implementations when available.

#### HACL*

[HACL*](https://github.com/mitls/hacl-star) is a formally verified cryptographic library, accessed via the [`rust-hacl-star`](https://github.com/quininer/rust-hacl-star) wrapper crate.

If you enable the `hacl-resolver` feature, Snow will include a `hacl_wrapper` module as well as a `HaclStarResolver` available to be used with `NoiseBuilder::with_resolver()`.

Similar to ring, if you enable the `hacl-accelerated` feature, Snow will default to choosing HACL* implementations when available.
