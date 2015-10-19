extern crate sodiumoxide;
extern crate crypto;

use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::hash::sha256;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};

const DHLEN : usize = 32;
const HASHLEN : usize = 32;
const BLOCKLEN : usize = 64;
const MACLEN : usize = 16;
const CIPHERKEYLEN : usize = 32;

fn zero_memory(out: &mut [u8]) {
    for count in 0..out.len() {out[count] = 0;}
}

fn copy_memory(data: &[u8], out: &mut [u8]) {
    for count in 0..data.len() {out[count] = data[count];}
}


struct KeyPair {
    privkey: [u8; DHLEN],
    pubkey: [u8; DHLEN]
}

fn GENERATE_KEYPAIR() -> KeyPair {
    KeyPair{privkey : [0; DHLEN], pubkey : [0; DHLEN]}
}

fn DH(keypair : &KeyPair, pubkey: &[u8]) -> [u8; DHLEN] {
    [0u8; DHLEN]
}


fn HASH(data: &[u8], out: &mut [u8]) {
    let mut hash = Sha256::new();
    hash.input(data);
    hash.result(out);
}

fn HMAC_HASH(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data);
    hmac.raw_result(out);
}

fn HKDF(chaining_key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut temp_key = [0u8; HASHLEN];
    let mut in2  = [0u8; HASHLEN];
    HMAC_HASH(chaining_key, data, &mut temp_key);
    HMAC_HASH(&temp_key, &[1u8], &mut out[0..HASHLEN]);
    copy_memory(out as &[u8], &mut in2);
    in2[HASHLEN] = 2;
    HMAC_HASH(&temp_key, &in2, &mut out[HASHLEN..2*HASHLEN]);
}


fn ENCRYPT(key: &[u8], nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
    zero_memory(&mut out[0..plaintext.len() + MACLEN]);
} 

fn DECRYPT(key: &[u8], nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
    zero_memory(&mut out[0..ciphertext.len() - MACLEN]);
    true
} 

enum Token {e, s, dhee, dhes, dhse, dhss}

enum NoiseError {DecryptError}

struct CipherState {
    k: [u8; CIPHERKEYLEN],
    n: u64
}

struct SymmetricState {
    cipherstate : CipherState,
    has_key : bool,
    ck: [u8; HASHLEN],
    h: [u8; HASHLEN]
}

struct HandshakeState {
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

    fn encrypt_and_increment(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        ENCRYPT(&self.k, self.n, authtext, plaintext, out);
        self.n += 1;
    }

    fn decrypt_and_increment(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> bool {
        if !DECRYPT(&self.k, self.n, authtext, ciphertext, out) {
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
            _ => HASH(handshake_name, &mut hname)
        }
        let cipherstate = CipherState::new();
        SymmetricState{cipherstate: cipherstate, has_key : false, ck : hname, h: hname}
    }

    fn mix_key(&mut self, data: &[u8]) {
        let mut hkdf_output = [0u8; 2*HASHLEN];
        HKDF(&self.ck, data, &mut hkdf_output);
        copy_memory(&hkdf_output[0..HASHLEN], &mut self.ck);
        copy_memory(&hkdf_output[HASHLEN..HASHLEN+CIPHERKEYLEN], &mut self.cipherstate.k);
        self.cipherstate.n = 0;
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut buffer = [0u8; 65535];
        copy_memory(&data, &mut buffer);
        copy_memory(&self.h, &mut buffer[data.len()..data.len() + HASHLEN]);
        HASH(&buffer, &mut self.h);
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
        HKDF(&self.ck, &[0u8; 0], &mut hkdf_output);
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();
        copy_memory( &hkdf_output[0..CIPHERKEYLEN], &mut c1.k);
        copy_memory( &hkdf_output[HASHLEN..HASHLEN+CIPHERKEYLEN], &mut c1.k);
        (c1, c2)
    }

}

impl HandshakeState {

    fn new(handshake_name: &[u8], new_s : KeyPair, new_e : KeyPair, new_rs: [u8; 32], new_re : [u8; 32] ) -> HandshakeState {
        let symmetricstate = SymmetricState::new(handshake_name); 
        HandshakeState{symmetricstate: symmetricstate, s: new_s, e: new_e, rs: new_rs, re: new_re}
    }

    fn write_handshake_message(&mut self, 
                               descriptor: &[Token], 
                               last: bool, 
                               payload: &[u8], 
                               out: &mut [u8]) -> Option<(CipherState, CipherState)> { 
        let mut index = 0;
        for token in descriptor {
            match (*token) {
                Token::e => {
                    self.e = GENERATE_KEYPAIR(); 
                    index += self.symmetricstate.encrypt_and_hash(&self.e.pubkey, &mut out[index..]); 
                },
                Token::s => index += self.symmetricstate.encrypt_and_hash(&self.s.pubkey, &mut out[index..]),
                Token::dhee => self.symmetricstate.mix_key(&DH(&self.e, &self.re)),
                Token::dhes => self.symmetricstate.mix_key(&DH(&self.e, &self.rs)),
                Token::dhse => self.symmetricstate.mix_key(&DH(&self.s, &self.re)),
                Token::dhss => self.symmetricstate.mix_key(&DH(&self.s, &self.rs)),
            }
        }
        self.symmetricstate.encrypt_and_hash(payload, &mut out[index..]);
        match last {
            true => Some(self.symmetricstate.split()),
            false => None 
        }
    }

    fn read_handshake_message(&mut self, 
                              buffer: &[u8], 
                              descriptor: &[Token], 
                              last: bool, 
                              out: &mut [u8]) -> Result<Option<(CipherState, CipherState)>, NoiseError> { 
        let mut ptr = buffer;
        for token in descriptor {
            match (*token) {
                Token::e | Token::s => {
                    let data = match self.symmetricstate.has_key {
                        true =>  {let temp = &ptr[..DHLEN+16]; ptr = &ptr[DHLEN+16..]; temp}
                        false => {let temp = &ptr[..DHLEN];    ptr = &ptr[DHLEN..];    temp}
                    };
                    if !self.symmetricstate.decrypt_and_hash(data, match (*token) {
                            Token::e => &mut self.re,
                            Token::s => &mut self.rs,
                            _ => unreachable!()}) {
                        return Err(NoiseError::DecryptError);
                    }
                },
                Token::dhee => self.symmetricstate.mix_key(&DH(&self.e, &self.re)),
                Token::dhes => self.symmetricstate.mix_key(&DH(&self.s, &self.re)),
                Token::dhse => self.symmetricstate.mix_key(&DH(&self.e, &self.rs)),
                Token::dhss => self.symmetricstate.mix_key(&DH(&self.s, &self.rs)),
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


