# Snow

[![Crates.io](https://img.shields.io/crates/v/snow.svg)](https://crates.io/crates/snow)
[![Docs.rs](https://docs.rs/snow/badge.svg)](https://docs.rs/snow)
[![Build Status](https://github.com/mcginty/snow/workflows/Build/badge.svg)](https://github.com/mcginty/snow/actions)
[![dependency status](https://deps.rs/repo/github/mcginty/snow/status.svg)](https://deps.rs/repo/github/mcginty/snow)

![totally official snow logo](https://i.imgur.com/gFgvo49.jpg?1)

An implementation of Trevor Perrin's [Noise Protocol](https://noiseprotocol.org/) that
is designed to be Hard To Fuck Up™.

🔥 **Warning** 🔥 This library has not received any formal audit.

## What's it look like?

See `examples/simple.rs` for a more complete TCP client/server example.

```rust
let mut noise = snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse()?)
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

Snow is currently tracking against [Noise spec revision 34](https://noiseprotocol.org/noise_rev34.html).

However, a not all features have been implemented yet (pull requests welcome):

- [ ] [The `fallback` modifier](https://noiseprotocol.org/noise_rev34.html#the-fallback-modifier)

## Crypto

Cryptographic providers are swappable through `Builder::with_resolver()`, but by default
it chooses select, artisanal pure-Rust implementations (see `Cargo.toml` for a quick
overview).

### Other Providers

#### ring

[ring](https://github.com/briansmith/ring) is a crypto library based off of BoringSSL
and is significantly faster than most of the pure-Rust implementations.

If you enable the `ring-resolver` feature, Snow will include a `resolvers::ring` module
as well as a `RingAcceleratedResolver` available to be used with
`Builder::with_resolver()`.

If you enable the `ring-accelerated` feature, Snow will default to choosing `ring`'s
crypto implementations when available.

### Resolver primitives supported

|            | default | ring |
| ---------: | :-----: | :--: |
|     CSPRNG |    ✔    |  ✔   |
|      25519 |    ✔    |  ✔   |
|        448 |         |      |
|      P-256 |    ✔    |      |
|     AESGCM |    ✔    |  ✔   |
| ChaChaPoly |    ✔    |  ✔   |
|     SHA256 |    ✔    |  ✔   |
|     SHA512 |    ✔    |  ✔   |
|    BLAKE2s |    ✔    |      |
|    BLAKE2b |    ✔    |      |

## `no_std` support and feature selection

Snow can be used in `no_std` environments if `alloc` is provided.

By default Snow uses the standard library, default cyprot resolver and a selected collection 
of crypto primitives. To use Snow in `no_std` environments or make other kinds of customized 
setups, use Snow with `default-features = false`. This way you will individually select 
the components you wish to use. `default-resolver` is the only built-in resolver that 
currently supports `no_std`.

To use a custom setup with `default-resolver`, enable your desired selection of cryptographic primitives:

| Primitive    | Feature flag           |
| :----------- | ---------------------: |
| **DH**                                |
| 25519        | `use-curve25519-dalek` |
| **Cipher**                            |
| AESGCM       | `use-aes-gcm`          |
| ChaChaPoly   | `use-chacha20poly1305` |
| XChaChaPoly* | `use-xchacha20poly1305`|
| **Hash**                              |
| SHA256       | `use-sha2`             |
| SHA512       | `use-sha2`             |
| BLAKE2s      | `use-blake2`           |
| BLAKE2b      | `use-blake2`           |

\* *XChaChaPoly*, an extended nonce variant of *ChaChaPoly*, is not in the official specification of Noise!

### Example configurations

**25519 + AES-GCM + SHA** with standard library features.
```toml
default-features = false
features = [
    "use-curve25519-dalek",
    "use-aes-gcm",
    "use-sha2",
    "std",
]
```

**25519 + ChaChaPoly + BLAKE2** without standard library.
```toml
default-features = false
features = [
    "use-curve25519-dalek",
    "use-chacha20poly1305",
    "use-blake2",
]
```

### `getrandom` support

Most crypto implementations supported by `default-resolver` will require 
[`getrandom`](getrandom).

If your target platform is not directly supported 
you might have to provide a custom implementation in your crate root. 
Check out their [documentation](getrandom-custom) for details.

[getrandom]: https://crates.io/crates/getrandom
[getrandom-custom]: https://docs.rs/getrandom/0.2.15/getrandom/macro.register_custom_getrandom.html

## License

Licensed under either of:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](https://opensource.org/license/mit/)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
