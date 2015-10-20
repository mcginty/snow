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
    let pubkey = curve25519_base(&privkey); 
    KeyPair{privkey : privkey, pubkey : pubkey}
}

fn dh(keypair : &KeyPair, pubkey: &[u8]) -> [u8; DHLEN] {
    curve25519(&keypair.privkey, pubkey)
}


pub fn hash(data: &[u8], out: &mut [u8]) {
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
    let mut in2  = [0u8; HASHLEN];
    hmac_hash(chaining_key, data, &mut temp_key);
    hmac_hash(&temp_key, &[1u8], &mut out[0..HASHLEN]);
    copy_memory(out as &[u8], &mut in2);
    in2[HASHLEN] = 2;
    hmac_hash(&temp_key, &in2, &mut out[HASHLEN..2*HASHLEN]);
}


fn encrypt(key: &[u8], nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
    let mut nonce_bytes = [0u8; 12];
    BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
    let mut cipher = AesGcm::new(KeySize::KeySize256, key, &nonce_bytes, authtext);
    let mut tag = [0u8; MACLEN];
    cipher.encrypt(plaintext, out, &mut tag);
    copy_memory(&tag, &mut out[plaintext.len()..]);
} 

fn decrypt(key: &[u8], nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
    let mut nonce_bytes = [0u8; 12];
    BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
    let mut cipher = AesGcm::new(KeySize::KeySize256, key, &nonce_bytes, authtext);
    let tag = [0u8; MACLEN];
    cipher.decrypt(ciphertext, out, &tag)
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

    fn new() -> CipherState {
        CipherState{k : [0; CIPHERKEYLEN], n:0}
    }

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
        let cipherstate = CipherState::new();
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
        let mut buffer = [0u8; 65535];
        copy_memory(&data, &mut buffer);
        copy_memory(&self.h, &mut buffer[data.len()..data.len() + HASHLEN]);
        hash(&buffer, &mut self.h);
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
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();
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
    use self::rustc_serialize::hex::ToHex;

    #[test]
    fn crypto_tests() {

        // SHA256 test
        let mut output = [0u8; 32];
        HASH("abc".as_bytes(), &mut output);
        assert!(output.to_hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");


    }
}
