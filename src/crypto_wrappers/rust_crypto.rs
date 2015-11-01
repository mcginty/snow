extern crate crypto;
extern crate byteorder;
extern crate rand;

use self::crypto::digest::Digest;
use self::crypto::sha2::{Sha256, Sha512};
use self::crypto::blake2b::Blake2b;
use self::crypto::aes::KeySize;
use self::crypto::aes_gcm::AesGcm;
use self::crypto::chacha20poly1305::ChaCha20Poly1305;
use self::crypto::aead::{AeadEncryptor, AeadDecryptor};
use self::crypto::curve25519::{curve25519, curve25519_base};

use self::byteorder::{ByteOrder, BigEndian, LittleEndian};
use self::rand::{OsRng, Rng};

use crypto_stuff::*;


pub struct Dh25519 {
    privkey : [u8; 32],
    pubkey  : [u8; 32]
}

pub struct CipherAESGCM {
    key : [u8; 32],
    nonce : u64
}

pub struct CipherChaChaPoly {
    key : [u8; 32],
    nonce : u64
}

pub struct HashSHA256 {
    hasher : Sha256
}

pub struct HashSHA512 {
    hasher : Sha512
}

pub struct HashBLAKE2b {
    hasher : Blake2b
}


impl Dh for Dh25519 {

    fn new(privkey: &[u8], pubkey: &[u8]) -> Dh25519 {
        let mut dh = Dh25519{privkey: [0u8; 32], pubkey: [0u8; 32]};
        copy_memory(privkey, &mut dh.privkey); /* RUSTSUCKS: Why can't I convert slice -> array? */
        copy_memory(pubkey, &mut dh.pubkey);
        dh
    }

    fn generate() -> Dh25519 {
        let mut privkey = [0u8; 32];
        let mut rng = OsRng::new().unwrap();
        rng.fill_bytes(&mut privkey);
        privkey[0] &= 248;
        privkey[31] &= 127;
        privkey[31] |= 64;
        let pubkey = curve25519_base(&privkey); 
        Dh25519{privkey : privkey, pubkey : pubkey}
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn dh(&self, pubkey: &[u8]) -> [u8; DHLEN] {
        curve25519(&self.privkey, pubkey)
    }

}

impl Cipher for CipherAESGCM {

    fn new(key: &[u8], nonce: u64) -> CipherAESGCM {
        let mut cipher = CipherAESGCM{key: [0u8; 32], nonce: nonce};
        copy_memory(key, &mut cipher.key);
        cipher
    }

    fn encrypt_and_inc(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], self.nonce);
        self.nonce += 1;
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let mut tag = [0u8; TAGLEN];
        cipher.encrypt(plaintext, &mut out[..plaintext.len()], &mut tag);
        copy_memory(&tag, &mut out[plaintext.len()..]);
    } 

    fn decrypt_and_inc(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], self.nonce);
        self.nonce += 1;
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let text_len = ciphertext.len() - TAGLEN;
        let mut tag = [0u8; TAGLEN];
        copy_memory(&ciphertext[text_len..], &mut tag);
        cipher.decrypt(&ciphertext[..text_len], &mut out[..text_len], &tag)
    } 

}

impl Cipher for CipherChaChaPoly {

    fn new(key: &[u8], nonce: u64) -> CipherChaChaPoly {
        let mut cipher = CipherChaChaPoly{key: [0u8; 32], nonce: nonce};
        copy_memory(key, &mut cipher.key);
        cipher
    }

    fn encrypt_and_inc(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes, self.nonce);
        self.nonce += 1;
        let mut cipher = ChaCha20Poly1305::new(&self.key, &nonce_bytes, authtext);
        let mut tag = [0u8; TAGLEN];
        cipher.encrypt(plaintext, &mut out[..plaintext.len()], &mut tag);
        copy_memory(&tag, &mut out[plaintext.len()..]);
    } 

    fn decrypt_and_inc(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes, self.nonce);
        self.nonce += 1;
        let mut cipher = ChaCha20Poly1305::new(&self.key, &nonce_bytes, authtext);
        let text_len = ciphertext.len() - TAGLEN;
        let mut tag = [0u8; TAGLEN];
        copy_memory(&ciphertext[text_len..], &mut tag);
        cipher.decrypt(&ciphertext[..text_len], &mut out[..text_len], &tag)
    } 

}

impl Hash for HashSHA256 {

    fn new() -> HashSHA256 {
        HashSHA256{hasher : Sha256::new()}
    }   

    fn block_len() -> usize {
        return 64;
    }

    fn hash_len() -> usize {
        return 32;
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.hasher.result(out);
    }
}

impl Hash for HashSHA512 {

    fn new() -> HashSHA512 {
        HashSHA512{hasher : Sha512::new()}
    }   

    fn block_len() -> usize {
        return 128;
    }

    fn hash_len() -> usize {
        return 64;
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.hasher.result(out);
    }
}

impl Hash for HashBLAKE2b {

    fn new() -> HashBLAKE2b {
        HashBLAKE2b{hasher : Blake2b::new(64)}
    }   

    fn block_len() -> usize {
        return 128;
    }

    fn hash_len() -> usize {
        return 64;
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.hasher.result(out);
    }
}


#[cfg(test)]
mod tests {

    extern crate rustc_serialize;

    use crypto_stuff::*;
    use super::*;
    use self::rustc_serialize::hex::{FromHex, ToHex};

    #[test]
    fn crypto_tests() {

        // SHA256 test
        {
            let mut output = [0u8; 32];
            let mut hasher = HashSHA256::new();
            hasher.input("abc".as_bytes());
            hasher.result(&mut output);
            assert!(output.to_hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        // HMAC-SHA256 test - RFC 4231
        {
            let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".from_hex().unwrap();
            let data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".from_hex().unwrap();
            let mut output = [0u8; 32];
            HashSHA256::hmac(&key, &data, &mut output);
            assert!(output.to_hex() == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        }

        // Curve25519 test - draft-curves-10
        {
            let mut keypair = Dh25519::new(&[0; 32], &[0; 32]);
            let scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".from_hex().unwrap();
            copy_memory(&scalar, &mut keypair.privkey);
            let public = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".from_hex().unwrap();
            let output = keypair.dh(&public);
            assert!(output.to_hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        }

        //AES256-GCM tests - gcm-spec.pdf
        {
            // Test Case 13
            let key = [0u8; 32];
            let nonce = 0u64;
            let plaintext = [0u8; 0];
            let authtext = [0u8; 0];
            let mut ciphertext = [0u8; 16];
            let mut cipher1 = CipherAESGCM::new(&key, nonce);
            cipher1.encrypt_and_inc(&authtext, &plaintext, &mut ciphertext);
            assert!(ciphertext.to_hex() == "530f8afbc74536b9a963b4f1c4cb738b");
            
            let mut resulttext = [0u8; 1];
            let mut cipher2 = CipherAESGCM::new(&key, nonce);
            assert!(cipher2.decrypt_and_inc(&authtext, &ciphertext, &mut resulttext) == true);
            assert!(resulttext[0] == 0);
            ciphertext[0] ^= 1;
            assert!(cipher1.nonce == 1 && cipher2.nonce == 1);
            cipher2.nonce = 0;
            assert!(cipher2.decrypt_and_inc(&authtext, &ciphertext, &mut resulttext) == false);

            // Test Case 14
            let plaintext2 = [0u8; 16];
            let mut ciphertext2 = [0u8; 32];
            let mut cipher3 = CipherAESGCM::new(&key, 0);
            cipher3.encrypt_and_inc(&authtext, &plaintext2, &mut ciphertext2);
            assert!(ciphertext2.to_hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
            
            let mut resulttext2 = [1u8; 16];
            let mut cipher4 = CipherAESGCM::new(&key, 0);
            assert!(cipher4.decrypt_and_inc(&authtext, &ciphertext2, &mut resulttext2) == true);
            assert!(plaintext2 == resulttext2);
            ciphertext2[0] ^= 1;
            assert!(cipher3.nonce == 1 && cipher4.nonce == 1);
            cipher4.nonce = 0;
            assert!(cipher4.decrypt_and_inc(&authtext, &ciphertext2, &mut resulttext2) == false);
        }

    }
}
