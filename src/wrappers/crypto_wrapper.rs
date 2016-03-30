extern crate crypto;
extern crate byteorder;
extern crate rustc_serialize;

use self::crypto::digest::Digest;
use self::crypto::mac::Mac;
use self::crypto::symmetriccipher::SynchronousStreamCipher;
use self::crypto::sha2::{Sha256, Sha512};
use self::crypto::blake2b::Blake2b;
use self::crypto::aes::KeySize;
use self::crypto::aes_gcm::AesGcm;
use self::crypto::chacha20::ChaCha20;
use self::crypto::poly1305::Poly1305;
use self::crypto::aead::{AeadEncryptor, AeadDecryptor};
use self::crypto::curve25519::{curve25519, curve25519_base};
use self::crypto::util::fixed_time_eq;

use self::byteorder::{ByteOrder, BigEndian, LittleEndian};
//use self::rustc_serialize::hex::{FromHex, ToHex};

use crypto_types::*;
use constants::*;
use utils::*;

pub struct Dh25519 {
    privkey : [u8; 32],
    pubkey  : [u8; 32],
}

pub struct CipherAESGCM {
    key : [u8; 32],
}

pub struct CipherChaChaPoly {
    key : [u8; 32],
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

impl Dh25519 {
    pub fn new() -> Dh25519 {
        Dh25519{privkey: [0u8; 32], pubkey: [0u8; 32]}
    }
}

impl DhType for Dh25519 {

    fn name(&self, out : &mut [u8]) -> usize { 
        copy_memory("25519".as_bytes(), out)
    }

    fn pub_len(&self) -> usize {
        return 32;
    }

    fn set(&mut self, privkey: &[u8], pubkey: &[u8]) {
        copy_memory(privkey, &mut self.privkey); /* RUSTSUCKS: Why can't I convert slice -> array? */
        copy_memory(pubkey, &mut self.pubkey);
    }

    fn generate(&mut self, rng: &mut RandomType) {
        rng.fill_bytes(&mut self.privkey);
        self.privkey[0] &= 248;
        self.privkey[31] &= 127;
        self.privkey[31] |= 64;
        let pubkey = curve25519_base(&self.privkey); 
        copy_memory(&pubkey, &mut self.pubkey);
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) {
        let result = curve25519(&self.privkey, pubkey);
        copy_memory(&result, out);
    }

}

impl CipherAESGCM {
    fn new() -> CipherAESGCM {
        CipherAESGCM{key: [0u8; 32]}
    }
}

impl CipherType for CipherAESGCM {

    fn name(&self, out : &mut [u8]) -> usize { 
        copy_memory("AESGCM".as_bytes(), out)
    }

    fn set(&mut self, key: &[u8]) {
        copy_memory(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let mut tag = [0u8; TAGLEN];
        cipher.encrypt(plaintext, &mut out[..plaintext.len()], &mut tag);
        copy_memory(&tag, &mut out[plaintext.len()..]);
    } 

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key, &nonce_bytes, authtext);
        let text_len = ciphertext.len() - TAGLEN;
        let mut tag = [0u8; TAGLEN];
        copy_memory(&ciphertext[text_len..], &mut tag);
        cipher.decrypt(&ciphertext[..text_len], &mut out[..text_len], &tag)
    } 

}

impl CipherChaChaPoly {
    fn new() -> CipherChaChaPoly {
        CipherChaChaPoly{key: [0u8; 32]}
    }
}

impl CipherType for CipherChaChaPoly {

    fn name(&self, out : &mut [u8]) -> usize { 
        copy_memory("ChaChaPoly".as_bytes(), out)
    }

    fn set(&mut self, key: &[u8]) {
        copy_memory(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes, nonce);

        let mut cipher = ChaCha20::new(&self.key, &nonce_bytes);
        let zeros = [0u8; 64];
        let mut poly_key = [0u8; 64];
        cipher.process(&zeros, &mut poly_key);
        cipher.process(plaintext, &mut out[..plaintext.len()]);
       
        let mut poly = Poly1305::new(&poly_key[..32]);
        poly.input(&authtext);
        let mut padding = [0u8; 16];
        poly.input(&padding[..(16 - (authtext.len() % 16)) % 16]);
        poly.input(&out[..plaintext.len()]);
        poly.input(&padding[..(16 - (plaintext.len() % 16)) % 16]);
        LittleEndian::write_u64(&mut padding, authtext.len() as u64);
        poly.input(&padding[..8]);
        LittleEndian::write_u64(&mut padding, plaintext.len() as u64);
        poly.input(&padding[..8]);
        poly.raw_result(&mut out[plaintext.len()..]);
    } 

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes, nonce);

        let mut cipher = ChaCha20::new(&self.key, &nonce_bytes);
        let zeros = [0u8; 64];
        let mut poly_key = [0u8; 64];
        cipher.process(&zeros, &mut poly_key);

        let mut poly = Poly1305::new(&poly_key[..32]);
        let mut padding = [0u8; 15];
        let text_len = ciphertext.len() - TAGLEN;
        poly.input(&authtext);
        poly.input(&padding[..(16 - (authtext.len() % 16)) % 16]);
        poly.input(&ciphertext[..text_len]);
        poly.input(&padding[..(16 - (text_len % 16)) % 16]);
        LittleEndian::write_u64(&mut padding, authtext.len() as u64);
        poly.input(&padding[..8]);
        LittleEndian::write_u64(&mut padding, text_len as u64);
        poly.input(&padding[..8]);
        let mut tag = [0u8; 16];
        poly.raw_result(&mut tag);
        if !fixed_time_eq(&tag, &ciphertext[text_len..]) {
            return false;
        }
        cipher.process(&ciphertext[..text_len], &mut out[..text_len]);
        true
    } 

}

impl HashSHA256 {
    fn new() -> HashSHA256 {
        HashSHA256{hasher: Sha256::new()}
    }
}

impl HashType for HashSHA256 {

    fn block_len(&self) -> usize {
        return 64;
    }

    fn hash_len(&self) -> usize {
        return 32;
    }

    fn name(&self, out : &mut [u8]) -> usize { 
        copy_memory("SHA256".as_bytes(), out)
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

impl HashSHA512 {
    fn new() -> HashSHA512 {
        HashSHA512{hasher: Sha512::new()}
    }
}

impl HashType for HashSHA512 {

    fn name(&self, out: &mut [u8]) -> usize { 
        copy_memory("SHA512".as_bytes(), out)
    }

    fn block_len(&self) -> usize {
        return 128;
    }

    fn hash_len(&self) -> usize {
        return 64;
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

impl HashBLAKE2b {
    fn new() -> HashBLAKE2b {
        HashBLAKE2b{hasher: Blake2b::new(64)}
    }
}

impl HashType for HashBLAKE2b {

    fn name(&self, out : &mut [u8]) -> usize { 
        copy_memory("BLAKE2b".as_bytes(), out)
    }

    fn block_len(&self) -> usize {
        return 128;
    }

    fn hash_len(&self) -> usize {
        return 64;
    }

    fn reset(&mut self) {
        self.hasher = Blake2b::new(64);
    }   

    fn input(&mut self, data: &[u8]) {
        crypto::digest::Digest::input(&mut self.hasher, data);
    }

    fn result(&mut self, out: &mut [u8]) {
        crypto::digest::Digest::result(&mut self.hasher, out);
    }
}


#[cfg(test)]
mod tests {

    extern crate rustc_serialize;

    use crypto_stuff::*;
    use super::*;
    use self::rustc_serialize::hex::{FromHex, ToHex};
    use super::crypto::poly1305::Poly1305;
    use super::crypto::mac::Mac;


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

        // HMAC-SHA256 and HMAC-SHA512 test - RFC 4231
        {
            let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".from_hex().unwrap();
            let data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".from_hex().unwrap();
            let mut output1 = [0u8; 32];
            HashSHA256::hmac(&key, &data, &mut output1);
            assert!(output1.to_hex() == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

            let mut output2 = [0u8; 64];
            HashSHA512::hmac(&key, &data, &mut output2);
            assert!(output2.to_hex() == "fa73b0089d56a284efb0f0756c890be9\
                                         b1b5dbdd8ee81a3655f83e33b2279d39\
                                         bf3e848279a722c806b485a47e67c807\
                                         b946a337bee8942674278859e13292fb");
        }

        // BLAKE2b test - draft-saarinen-blake2-06
        {
            let mut output = [0u8; 64];
            let mut hasher = HashBLAKE2b::new();
            hasher.input("abc".as_bytes());
            hasher.result(&mut output);
            assert!(output.to_hex() == "ba80a53f981c4d0d6a2797b69f12f6e9\
                                        4c212f14685ac4b74b12bb6fdbffa2d1\
                                        7d87c5392aab792dc252d5de4533cc95\
                                        18d38aa8dbf1925ab92386edd4009923"); 
        }

        // Curve25519 test - draft-curves-10
        {
            let mut keypair = Dh25519::new();
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
            let mut cipher1 = CipherState::<CipherAESGCM>::new(&key, nonce);
            cipher1.encrypt_ad(&authtext, &plaintext, &mut ciphertext);
            assert!(ciphertext.to_hex() == "530f8afbc74536b9a963b4f1c4cb738b");
            
            let mut resulttext = [0u8; 1];
            let mut cipher2 = CipherState::<CipherAESGCM>::new(&key, nonce);
            assert!(cipher2.decrypt_ad(&authtext, &ciphertext, &mut resulttext) == true);
            assert!(resulttext[0] == 0);
            ciphertext[0] ^= 1;
            assert!(cipher1.n == 1 && cipher2.n == 1);
            cipher2.n = 0;
            assert!(cipher2.decrypt_ad(&authtext, &ciphertext, &mut resulttext) == false);

            // Test Case 14
            let plaintext2 = [0u8; 16];
            let mut ciphertext2 = [0u8; 32];
            let mut cipher3 = CipherState::<CipherAESGCM>::new(&key, 0);
            cipher3.encrypt_ad(&authtext, &plaintext2, &mut ciphertext2);
            assert!(ciphertext2.to_hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
            
            let mut resulttext2 = [1u8; 16];
            let mut cipher4 = CipherState::<CipherAESGCM>::new(&key, 0);
            assert!(cipher4.decrypt_ad(&authtext, &ciphertext2, &mut resulttext2) == true);
            assert!(plaintext2 == resulttext2);
            ciphertext2[0] ^= 1;
            assert!(cipher3.n == 1 && cipher4.n == 1);
            cipher4.n = 0;
            assert!(cipher4.decrypt_ad(&authtext, &ciphertext2, &mut resulttext2) == false);
        }

        // Poly1305 internal test - RFC 7539
        {
            let key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b".from_hex().unwrap();
            let msg = "43727970746f6772617068696320466f\
                       72756d2052657365617263682047726f\
                       7570".from_hex().unwrap();                                          
            let mut poly = Poly1305::new(&key);
            poly.input(&msg);
            let mut output = [0u8; 16];
            poly.raw_result(&mut output);
            assert!(output.to_hex() == "a8061dc1305136c6c22b8baf0c0127a9");
        }

        //ChaChaPoly round-trip test, empty plaintext
        {
            let key = [0u8; 32];
            let nonce = 0u64;
            let plaintext = [0u8; 0];
            let authtext = [0u8; 0];
            let mut ciphertext = [0u8; 16];
            let mut cipher1 = CipherState::<CipherChaChaPoly>::new(&key, nonce);
            cipher1.encrypt_ad(&authtext, &plaintext, &mut ciphertext);

            let mut resulttext = [0u8; 1];
            let mut cipher2 = CipherState::<CipherChaChaPoly>::new(&key, nonce);
            assert!(cipher2.decrypt_ad(&authtext, &ciphertext, &mut resulttext) == true);
            assert!(resulttext[0] == 0);
            ciphertext[0] ^= 1;
            assert!(cipher1.n == 1 && cipher2.n == 1);
            cipher2.n = 0;
            assert!(cipher2.decrypt_ad(&authtext, &ciphertext, &mut resulttext) == false);
        }
        
        //ChaChaPoly round-trip test, non-empty plaintext
        {
            let key = [0u8; 32];
            let nonce = 0u64;
            let plaintext = [0x34u8; 117];
            let authtext = [0u8; 0];
            let mut ciphertext = [0u8; 133];
            let mut cipher1 = CipherState::<CipherChaChaPoly>::new(&key, nonce);
            cipher1.encrypt_ad(&authtext, &plaintext, &mut ciphertext);

            let mut resulttext = [0u8; 117];
            let mut cipher2 = CipherState::<CipherChaChaPoly>::new(&key, nonce);
            assert!(cipher2.decrypt_ad(&authtext, &ciphertext, &mut resulttext) == true);
            assert!(resulttext.to_hex() == plaintext.to_hex());
        }

        //ChaChaPoly known-answer test - RFC 7539
        {
            let key ="1c9240a5eb55d38af333888604f6b5f0\
                      473917c1402b80099dca5cbc207075c0".from_hex().unwrap();
            let nonce = 0x0807060504030201u64;
            let ciphertext ="64a0861575861af460f062c79be643bd\
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
                             a6ad5cb4022b02709b".from_hex().unwrap();
            let tag = "eead9d67890cbb22392336fea1851f38".from_hex().unwrap();
            let authtext = "f33388860000000000004e91".from_hex().unwrap();
            let mut combined_text = [0u8; 1024];    
            let mut out = [0u8; 1024];
            copy_memory(&ciphertext, &mut combined_text);
            copy_memory(&tag[0..TAGLEN], &mut combined_text[ciphertext.len()..]);
            
            let mut cipher = CipherState::<CipherChaChaPoly>::new(&key, nonce);
            assert!(cipher.decrypt_ad(&authtext, &combined_text[..ciphertext.len()+TAGLEN], &mut out[..ciphertext.len()]));
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
            assert!(out[..ciphertext.len()].to_hex() == desired_plaintext);
        }

    }
}
