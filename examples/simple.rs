extern crate snow;

use snow::*;

fn main() {
    let builder = NoiseBuilder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap());
    let my_private_key = builder.generate_private_key().unwrap();
    let mut noise = builder.local_private_key(&my_private_key)
                           .build_initiator()
                           .unwrap();

    let mut buf = vec![0u8; 65535];

    let len = noise.write_message("abcdef".as_bytes(), &mut buf).unwrap();
    println!("first message: {:?}", &buf[..len]);
}