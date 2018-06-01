extern crate crypto;
extern crate blake2_rfc;
extern crate chacha20_poly1305_aead;
extern crate x25519_dalek;

use self::crypto::digest::Digest;
use self::crypto::sha2::{Sha256, Sha512};
use self::crypto::aes::KeySize;
use self::crypto::aes_gcm::AesGcm;
use self::crypto::aead::{AeadEncryptor, AeadDecryptor};
use self::blake2_rfc::blake2b::Blake2b;
use self::blake2_rfc::blake2s::Blake2s;
use self::x25519_dalek as x25519;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

use types::*;
use constants::*;
use utils::copy_memory;
use std::io::{Cursor, Write};

#[derive(Default)]
pub struct Dh25519 {
    privkey: [u8; 32],
    pubkey:  [u8; 32],
}

#[derive(Clone, Default)]
pub struct CipherAESGCM {
    key: [u8; 32],
}

#[derive(Clone, Default)]
pub struct CipherChaChaPoly {
    key: [u8; 32],
}

pub struct HashSHA256 {
    hasher: Sha256
}

pub struct HashSHA512 {
    hasher: Sha512
}

pub struct HashBLAKE2b {
    hasher: Blake2b
}

pub struct HashBLAKE2s {
    hasher: Blake2s
}

impl Dh for Dh25519 {

    fn name(&self) -> &'static str {
        static NAME: &'static str = "25519";
        NAME
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        copy_memory(privkey, &mut self.privkey);
        let pubkey = x25519::generate_public(&self.privkey);
        copy_memory(pubkey.as_bytes(), &mut self.pubkey);
    }

    fn generate(&mut self, rng: &mut Random) {
        rng.fill_bytes(&mut self.privkey);
        let pubkey = x25519::generate_public(&self.privkey);
        copy_memory(pubkey.as_bytes(), &mut self.pubkey);
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) {
        let result = x25519::diffie_hellman(&self.privkey, array_ref![pubkey, 0, 32]);
        copy_memory(&result, out);
    }
}

impl Cipher for CipherAESGCM {

    fn name(&self) -> &'static str {
        static NAME: &'static str = "AESGCM";
        NAME
    }

    fn set(&mut self, key: &[u8]) {
        copy_memory(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let mut tag = [0u8; TAGLEN];
        cipher.encrypt(plaintext, &mut out[..plaintext.len()], &mut tag);
        copy_memory(&tag, &mut out[plaintext.len()..]);
        plaintext.len() + TAGLEN
    } 

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> Result<usize, ()> {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let text_len = ciphertext.len() - TAGLEN;
        let mut tag = [0u8; TAGLEN];
        copy_memory(&ciphertext[text_len..], &mut tag);
        if cipher.decrypt(&ciphertext[..text_len], &mut out[..text_len], &tag) {
            Ok(text_len)
        } else {
            Err(())
        }
    }
}

impl Cipher for CipherChaChaPoly {

    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        copy_memory(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut buf = Cursor::new(out);
        let tag = chacha20_poly1305_aead::encrypt(&self.key, &nonce_bytes, authtext, plaintext, &mut buf);
        let tag = tag.unwrap();
        buf.write_all(&tag).unwrap();
        if buf.position() > usize::max_value() as u64 {
            panic!("usize overflow");
        } else {
            buf.position() as usize
        }
    }

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut buf = Cursor::new(out);
        let result = chacha20_poly1305_aead::decrypt(
            &self.key,
            &nonce_bytes,
            authtext,
            &ciphertext[..ciphertext.len()-TAGLEN],
            &ciphertext[ciphertext.len()-TAGLEN..],
            &mut buf);
        match result {
            Ok(_) => {
                if buf.position() > usize::max_value() as u64 {
                    panic!("usize overflow");
                } else {
                    Ok(buf.position() as usize)
                }
            }
            Err(_) => Err(()),
        }
    }
}

impl Default for HashSHA256 {
    fn default() -> HashSHA256 {
        HashSHA256{hasher: Sha256::new()}
    }
}

impl Hash for HashSHA256 {

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }   

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.hasher.result(out);
    }
}

impl Default for HashSHA512 {
    fn default() -> HashSHA512 {
        HashSHA512{hasher:Sha512::new()}
    }
}

impl Hash for HashSHA512 {

    fn name(&self) -> &'static str {
        "SHA512"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.hasher = Sha512::new();
    }   

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.hasher.result(out);
    }
}

impl Default for HashBLAKE2b {
    fn default() -> HashBLAKE2b {
        HashBLAKE2b { hasher: Blake2b::new(64) }
    }
}

impl Hash for HashBLAKE2b {

    fn name(&self) -> &'static str {
        "BLAKE2b"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.hasher = Blake2b::new(64);
    }   

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.clone().finalize();
        out[..64].copy_from_slice(hash.as_bytes());
    }
}

impl Default for HashBLAKE2s {
    fn default() -> HashBLAKE2s {
        HashBLAKE2s { hasher: Blake2s::new(32) }
    }
}

impl Hash for HashBLAKE2s {

    fn name(&self) -> &'static str {
        "BLAKE2s"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.hasher = Blake2s::new(32);
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.clone().finalize();
        out[..32].copy_from_slice(hash.as_bytes());
    }
}


#[cfg(test)]
mod tests {

    extern crate hex;

    use types::*;
    use super::*;
    use self::hex::{FromHex, ToHex};
    use super::crypto::poly1305::Poly1305;
    use super::crypto::mac::Mac;

    #[test]
    fn test_sha256() {
        let mut output = [0u8; 32];
        let mut hasher:HashSHA256 = Default::default();
        hasher.input("abc".as_bytes());
        hasher.result(&mut output);
        assert!(output.to_hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_hmac_sha256_sha512() {
        let key = Vec::<u8>::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = Vec::<u8>::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let mut output1 = [0u8; 32];
        let mut hasher: HashSHA256 = Default::default();
        hasher.hmac(&key, &data, &mut output1);
        assert!(output1.to_hex() == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

        let mut output2 = [0u8; 64];
        let mut hasher: HashSHA512 = Default::default();
        hasher.hmac(&key, &data, &mut output2);
        assert!(output2.to_vec().to_hex() == "fa73b0089d56a284efb0f0756c890be9\
                                     b1b5dbdd8ee81a3655f83e33b2279d39\
                                     bf3e848279a722c806b485a47e67c807\
                                     b946a337bee8942674278859e13292fb");
    }

    #[test]
    fn test_blake2b() {
        // BLAKE2b test - draft-saarinen-blake2-06
        let mut output = [0u8; 64];
        let mut hasher:HashBLAKE2b = Default::default();
        hasher.input("abc".as_bytes());
        hasher.result(&mut output);
        assert!(output.to_vec().to_hex() == "ba80a53f981c4d0d6a2797b69f12f6e9\
                                    4c212f14685ac4b74b12bb6fdbffa2d1\
                                    7d87c5392aab792dc252d5de4533cc95\
                                    18d38aa8dbf1925ab92386edd4009923");
    }

    #[test]
    fn test_blake2s() {
        // BLAKE2s test - draft-saarinen-blake2-06
        let mut output = [0u8; 32];
        let mut hasher:HashBLAKE2s = Default::default();
        hasher.input("abc".as_bytes());
        hasher.result(&mut output);
        assert!(output.to_hex() == "508c5e8c327c14e2e1a72ba34eeb452f\
                    37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn test_curve25519() {
    // Curve25519 test - draft-curves-10
        let mut keypair:Dh25519 = Default::default();
        let scalar = Vec::<u8>::from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap();
        copy_memory(&scalar, &mut keypair.privkey);
        let public = Vec::<u8>::from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
        let mut output = [0u8; 32];
        keypair.dh(&public, &mut output);
        assert!(output.to_hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    #[test]
    fn test_aes256_gcm() {
    //AES256-GCM tests - gcm-spec.pdf
        // Test Case 13
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        let mut cipher1: CipherAESGCM = Default::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);
        assert!(ciphertext.to_hex() == "530f8afbc74536b9a963b4f1c4cb738b");

        let mut resulttext = [0u8; 1];
        let mut cipher2: CipherAESGCM = Default::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(resulttext[0] == 0);
        ciphertext[0] ^= 1;
        assert!(cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).is_err());

        // Test Case 14
        let plaintext2 = [0u8; 16];
        let mut ciphertext2 = [0u8; 32];
        let mut cipher3: CipherAESGCM = Default::default();
        cipher3.set(&key);
        cipher3.encrypt(nonce, &authtext, &plaintext2, &mut ciphertext2);
        assert!(ciphertext2.to_hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        let mut resulttext2 = [1u8; 16];
        let mut cipher4: CipherAESGCM = Default::default();
        cipher4.set(&key);
        cipher4.decrypt(nonce, &authtext, &ciphertext2, &mut resulttext2).unwrap();
        assert!(plaintext2 == resulttext2);
        ciphertext2[0] ^= 1;
        assert!(cipher4.decrypt(nonce, &authtext, &ciphertext2, &mut resulttext2).is_err());
    }

    #[test]
    fn test_poly1305() {
    // Poly1305 internal test - RFC 7539
        let key = Vec::<u8>::from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let msg = Vec::<u8>::from_hex("43727970746f6772617068696320466f\
                   72756d2052657365617263682047726f\
                   7570").unwrap();
        let mut poly = Poly1305::new(&key);
        poly.input(&msg);
        let mut output = [0u8; 16];
        poly.raw_result(&mut output);
        assert!(output.to_hex() == "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn test_chachapoly_empty() {
    //ChaChaPoly round-trip test, empty plaintext
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        let mut cipher1 : CipherChaChaPoly = Default::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 1];
        let mut cipher2 : CipherChaChaPoly = Default::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(resulttext[0] == 0);
        ciphertext[0] ^= 1;
        assert!(cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).is_err());
    }

    #[test]
    fn test_chachapoly_nonempty() {
    //ChaChaPoly round-trip test, non-empty plaintext
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0x34u8; 117];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 133];
        let mut cipher1 : CipherChaChaPoly = Default::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 117];
        let mut cipher2 : CipherChaChaPoly = Default::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(resulttext.to_vec().to_hex() == plaintext.to_vec().to_hex());
    }

    #[test]
    fn test_chachapoly_known_answer() {
    //ChaChaPoly known-answer test - RFC 7539
        let key =Vec::<u8>::from_hex("1c9240a5eb55d38af333888604f6b5f0\
                  473917c1402b80099dca5cbc207075c0").unwrap();
        let nonce = 0x0807060504030201u64;
        let ciphertext =Vec::<u8>::from_hex("64a0861575861af460f062c79be643bd\
                         5e805cfd345cf389f108670ac76c8cb2\
                         4c6cfc18755d43eea09ee94e382d26b0\
                         bdb7b73c321b0100d4f03b7f355894cf\
                         332f830e710b97ce98c8a84abd0b9481\
                         14ad176e008d33bd60f982b1ff37c855\
                         9797a06ef4f0ef61c186324e2b350638\
                         3606907b6a7c02b0f9f6157b53c867e4\
                         b9166c767b804d46a59b5216cde7a4e9\
                         9040c5a40433225ee282a1b0a06c523e\
                         af4534d7f83fa1155b0047718cbc546a\
                         0d072b04b3564eea1b422273f548271a\
                         0bb2316053fa76991955ebd63159434e\
                         cebb4e466dae5a1073a6727627097a10\
                         49e617d91d361094fa68f0ff77987130\
                         305beaba2eda04df997b714d6c6f2c29\
                         a6ad5cb4022b02709b").unwrap();
        let tag = Vec::<u8>::from_hex("eead9d67890cbb22392336fea1851f38").unwrap();
        let authtext = Vec::<u8>::from_hex("f33388860000000000004e91").unwrap();
        let mut combined_text = [0u8; 1024];
        let mut out = [0u8; 1024];
        copy_memory(&ciphertext, &mut combined_text);
        copy_memory(&tag[0..TAGLEN], &mut combined_text[ciphertext.len()..]);

        let mut cipher : CipherChaChaPoly = Default::default();
        cipher.set(&key);
        cipher.decrypt(nonce, &authtext, &combined_text[..ciphertext.len()+TAGLEN], &mut out[..ciphertext.len()]).unwrap();
        let desired_plaintext = "496e7465726e65742d44726166747320\
                                 61726520647261667420646f63756d65\
                                 6e74732076616c696420666f72206120\
                                 6d6178696d756d206f6620736978206d\
                                 6f6e74687320616e64206d6179206265\
                                 20757064617465642c207265706c6163\
                                 65642c206f72206f62736f6c65746564\
                                 206279206f7468657220646f63756d65\
                                 6e747320617420616e792074696d652e\
                                 20497420697320696e617070726f7072\
                                 6961746520746f2075736520496e7465\
                                 726e65742d4472616674732061732072\
                                 65666572656e6365206d617465726961\
                                 6c206f7220746f206369746520746865\
                                 6d206f74686572207468616e20617320\
                                 2fe2809c776f726b20696e2070726f67\
                                 726573732e2fe2809d";
        assert!(out[..ciphertext.len()].to_owned().to_hex() == desired_plaintext);
    }
}
