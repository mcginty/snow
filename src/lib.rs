extern crate crypto;
extern crate byteorder;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use crypto::mac::{Mac};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::curve25519::{curve25519, curve25519_base};

use byteorder::{ByteOrder, BigEndian};
use rand::{OsRng, Rng};

const DHLEN : usize = 32;
const HASHLEN : usize = 32;
//const BLOCKLEN : usize = 64;
const MACLEN : usize = 16;
const CIPHERKEYLEN : usize = 32;
const MAXMSGLEN : usize = 65535;

fn copy_memory(data: &[u8], out: &mut [u8]) {
    for count in 0..data.len() {out[count] = data[count];}
}


pub struct KeyPair {
    privkey: [u8; DHLEN],
    pubkey: [u8; DHLEN]
}

pub fn generate_keypair() -> KeyPair {
    let mut privkey = [0u8; 32];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut privkey);
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;
    let pubkey = curve25519_base(&privkey); 
    KeyPair{privkey : privkey, pubkey : pubkey}
}

fn dh(keypair : &KeyPair, pubkey: &[u8]) -> [u8; DHLEN] {
    curve25519(&keypair.privkey, pubkey)
}


fn hash(data: &[u8], out: &mut [u8]) {
    let mut h = Sha256::new();
    h.input(data);
    h.result(out);
}

fn hmac_hash(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data);
    hmac.raw_result(out);
}

fn hkdf(chaining_key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut temp_key = [0u8; HASHLEN];
    let mut in2 = [0u8; HASHLEN+1];
    hmac_hash(chaining_key, data, &mut temp_key);
    hmac_hash(&temp_key, &[1u8], &mut out[0..HASHLEN]);
    copy_memory(&out[0..HASHLEN], &mut in2);
    in2[HASHLEN] = 2;
    hmac_hash(&temp_key, &in2, &mut out[HASHLEN..2*HASHLEN]);
}


fn encrypt(key: &[u8], nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
    let mut nonce_bytes = [0u8; 12];
    BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
    let mut cipher = AesGcm::new(KeySize::KeySize256, key, &nonce_bytes, authtext);
    let mut tag = [0u8; MACLEN];
    cipher.encrypt(plaintext, &mut out[..plaintext.len()], &mut tag);
    copy_memory(&tag, &mut out[plaintext.len()..]);
} 

fn decrypt(key: &[u8], nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
    let mut nonce_bytes = [0u8; 12];
    BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
    let mut cipher = AesGcm::new(KeySize::KeySize256, key, &nonce_bytes, authtext);
    let text_len = ciphertext.len() - MACLEN;
    let mut tag = [0u8; MACLEN];
    copy_memory(&ciphertext[text_len..], &mut tag);
    cipher.decrypt(&ciphertext[..text_len], &mut out[..text_len], &tag)
} 

pub enum Token {E, S, Dhee, Dhes, Dhse, Dhss}

pub enum NoiseError {DecryptError}

pub struct CipherState {
    k: [u8; CIPHERKEYLEN],
    n: u64
}

struct SymmetricState {
    cipherstate : CipherState,
    has_key : bool,
    ck: [u8; HASHLEN],
    h: [u8; HASHLEN]
}

pub struct HandshakeState {
    symmetricstate: SymmetricState,
    s: KeyPair,
    e: KeyPair,
    rs: [u8; DHLEN],
    re: [u8; DHLEN],
}


impl CipherState {

    pub fn encrypt_and_increment(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        encrypt(&self.k, self.n, authtext, plaintext, out);
        self.n += 1;
    }

    pub fn decrypt_and_increment(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> bool {
        if !decrypt(&self.k, self.n, authtext, ciphertext, out) {
            self.n += 1;
            return false;
        }
        self.n += 1;
        true
    } 
}

impl SymmetricState {

    fn new(handshake_name: &[u8]) -> SymmetricState {
        let mut hname = [0u8; HASHLEN];
        match handshake_name.len() {
            0 ... HASHLEN => copy_memory(handshake_name, &mut hname),
            _ => hash(handshake_name, &mut hname)
        }
        let cipherstate = CipherState{k : [0; CIPHERKEYLEN], n:0};
        SymmetricState{cipherstate: cipherstate, has_key : false, ck : hname, h: hname}
    }

    fn mix_key(&mut self, data: &[u8]) {
        let mut hkdf_output = [0u8; 2*HASHLEN];
        hkdf(&self.ck, data, &mut hkdf_output);
        copy_memory(&hkdf_output[0..HASHLEN], &mut self.ck);
        copy_memory(&hkdf_output[HASHLEN..HASHLEN+CIPHERKEYLEN], &mut self.cipherstate.k);
        self.cipherstate.n = 0;
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut buffer = [0u8; HASHLEN + MAXMSGLEN];
        copy_memory(&self.h, &mut buffer);
        copy_memory(&data, &mut buffer[HASHLEN..]);
        hash(&buffer[..HASHLEN + data.len()], &mut self.h);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        if self.has_key {
            self.cipherstate.encrypt_and_increment(&self.h, plaintext, out);
            self.mix_hash(&out[..plaintext.len() + MACLEN]);
            return plaintext.len() + MACLEN;
        } else {
            copy_memory(plaintext, out);
            self.mix_hash(plaintext);
            return plaintext.len();
        }
    }

    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        if self.has_key {
            if !self.cipherstate.decrypt_and_increment(&self.h, data, out) {
                return false;
            }
            self.mix_hash(data);
        } else {
            copy_memory(data, out);
            self.mix_hash(data);
        }
        true
    }

    fn split(&self) -> (CipherState, CipherState) {
        let mut hkdf_output = [0u8; 2*HASHLEN];
        hkdf(&self.ck, &[0u8; 0], &mut hkdf_output);
        let mut c1 = CipherState{k : [0; CIPHERKEYLEN], n:0};
        let mut c2 = CipherState{k : [0; CIPHERKEYLEN], n:0};
        copy_memory( &hkdf_output[0..CIPHERKEYLEN], &mut c1.k);
        copy_memory( &hkdf_output[HASHLEN..HASHLEN+CIPHERKEYLEN], &mut c2.k);
        (c1, c2)
    }

}

impl HandshakeState {

    pub fn new(handshake_name: &[u8], new_s : KeyPair, new_e : KeyPair, new_rs: [u8; 32], new_re : [u8; 32] ) -> HandshakeState {
        let symmetricstate = SymmetricState::new(handshake_name); 
        HandshakeState{symmetricstate: symmetricstate, s: new_s, e: new_e, rs: new_rs, re: new_re}
    }

    pub fn write_handshake_message(&mut self, 
                               descriptor: &[Token], 
                               last: bool, 
                               payload: &[u8], 
                               out: &mut [u8]) -> Option<(CipherState, CipherState)> { 
        let mut index = 0;
        for token in descriptor {
            match *token {
                Token::E => {
                    self.e = generate_keypair(); 
                    index += self.symmetricstate.encrypt_and_hash(&self.e.pubkey, &mut out[index..]); 
                },
                Token::S => index += self.symmetricstate.encrypt_and_hash(&self.s.pubkey, &mut out[index..]),
                Token::Dhee => self.symmetricstate.mix_key(&dh(&self.e, &self.re)),
                Token::Dhes => self.symmetricstate.mix_key(&dh(&self.e, &self.rs)),
                Token::Dhse => self.symmetricstate.mix_key(&dh(&self.s, &self.re)),
                Token::Dhss => self.symmetricstate.mix_key(&dh(&self.s, &self.rs)),
            }
        }
        self.symmetricstate.encrypt_and_hash(payload, &mut out[index..]);
        match last {
            true => Some(self.symmetricstate.split()),
            false => None 
        }
    }

    pub fn read_handshake_message(&mut self, 
                              buffer: &[u8], 
                              descriptor: &[Token], 
                              last: bool, 
                              out: &mut [u8]) -> Result<Option<(CipherState, CipherState)>, NoiseError> { 
        let mut ptr = buffer;
        for token in descriptor {
            match *token {
                Token::E | Token::S => {
                    let data = match self.symmetricstate.has_key {
                        true =>  {let temp = &ptr[..DHLEN+16]; ptr = &ptr[DHLEN+16..]; temp}
                        false => {let temp = &ptr[..DHLEN];    ptr = &ptr[DHLEN..];    temp}
                    };
                    if !self.symmetricstate.decrypt_and_hash(data, match *token {
                            Token::E => &mut self.re,
                            Token::S => &mut self.rs,
                            _ => unreachable!()}) {
                        return Err(NoiseError::DecryptError);
                    }
                },
                Token::Dhee => self.symmetricstate.mix_key(&dh(&self.e, &self.re)),
                Token::Dhes => self.symmetricstate.mix_key(&dh(&self.s, &self.re)),
                Token::Dhse => self.symmetricstate.mix_key(&dh(&self.e, &self.rs)),
                Token::Dhss => self.symmetricstate.mix_key(&dh(&self.s, &self.rs)),
            }
        }
        if !self.symmetricstate.decrypt_and_hash(ptr, out) {
            return Err(NoiseError::DecryptError);
        }
        match last {
            true => Ok(Some(self.symmetricstate.split())),
            false => Ok(None) 
        }
    }

}




#[cfg(test)]
mod tests {

    extern crate rustc_serialize;

    use super::*;
    use super::{hash, hmac_hash, dh, encrypt, decrypt};
    use super::copy_memory;
    use self::rustc_serialize::hex::{FromHex, ToHex};
    

    #[test]
    fn crypto_tests() {

        // SHA256 test
        {
            let mut output = [0u8; 32];
            hash("abc".as_bytes(), &mut output);
            assert!(output.to_hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        // HMAC-SHA256 test - RFC 4231
        {
            let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".from_hex().unwrap();
            let data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".from_hex().unwrap();
            let mut output = [0u8; 32];
            hmac_hash(&key, &data, &mut output);
            println!("{}, {}, {}", key.len(), data.len(), output.to_hex());
            assert!(output.to_hex() == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        }

        // Curve25519 test - draft-curves-10
        {
            let scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".from_hex().unwrap();
            let mut keypair = KeyPair{privkey: [0; 32], pubkey: [0; 32]};
            copy_memory(&scalar, &mut keypair.privkey);
            let public = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".from_hex().unwrap();
            let output = dh(&keypair, &public);
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
            encrypt(&key, nonce, &authtext, &plaintext, &mut ciphertext);
            assert!(ciphertext.to_hex() == "530f8afbc74536b9a963b4f1c4cb738b");
            
            let mut resulttext = [0u8; 1];
            assert!(decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext) == true);
            assert!(resulttext[0] == 0);
            ciphertext[0] ^= 1;
            assert!(decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext) == false);

            // Test Case 14
            let plaintext2 = [0u8; 16];
            let mut ciphertext2 = [0u8; 32];
            encrypt(&key, nonce, &authtext, &plaintext2, &mut ciphertext2);
            assert!(ciphertext2.to_hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
            
            let mut resulttext2 = [1u8; 16];
            assert!(decrypt(&key, nonce, &authtext, &ciphertext2, &mut resulttext2) == true);
            assert!(plaintext2 == resulttext2);
            ciphertext2[0] ^= 1;
            assert!(decrypt(&key, nonce, &authtext, &ciphertext2, &mut resulttext2) == false);
        }

    }
}
