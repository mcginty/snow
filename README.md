
# Snow

An implementation of the Noise Protocol by Trevor Perrin that is designed to be
Hard To Fuck Up™.

# What's it look like?
See `examples/simple.rs` for a more complete TCP client/server example.

```rust
let noise = NoiseBuilder::new("Noise_NN_ChaChaPoly_BLAKE2s".parse().unwrap())
                         .build_initiator()
                         .unwrap();

let mut buf = [0u8; 65535];

// write first handshake message
noise.write_message(&[0u8; 0], &mut buf).unwrap();

// receive response message
let incoming = receive_message_from_the_mysterious_ether();
noise.read_message(&incoming, &mut buf).unwrap();

// complete handshake, and transition the state machine into transport mode
let noise = noise.into_transport_mode();
```

## Status

Work in progress. Unreviewed. Unaudited. All APIs are unstable. Don't use for security critical purposes.
