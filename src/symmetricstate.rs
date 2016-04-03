extern crate rustc_serialize;

use utils::*;
use constants::*;
use crypto_types::*;
use cipherstate::*;
use self::rustc_serialize::hex::{FromHex, ToHex};

pub trait SymmetricStateType {
    fn cipher_name(&self, out : &mut [u8]) -> usize;
    fn hash_name(&self, out : &mut [u8]) -> usize;
    fn initialize(&mut self, handshake_name: &[u8]);
    fn mix_key(&mut self, data: &[u8]);
    fn mix_hash(&mut self, data: &[u8]);
    fn mix_preshared_key(&mut self, psk: &[u8]);
    fn has_key(&self) -> bool;
    fn has_preshared_key(&self) -> bool;
    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize;
    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool;
    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType);
}

pub struct SymmetricState<'a> {
    cipherstate : &'a mut CipherStateType,
    hasher: &'a mut HashType,
    h : [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    ck: [u8; MAXHASHLEN], /* Change once Rust has trait-associated consts */
    has_key: bool,
    has_preshared_key: bool,
}

impl<'a> SymmetricState<'a> {
    pub fn new(cipherstate : &'a mut CipherStateType, hasher: &'a mut HashType) -> SymmetricState<'a> {
        SymmetricState{
            cipherstate: cipherstate,
            hasher: hasher,
            h: [0u8; MAXHASHLEN],
            ck : [0u8; MAXHASHLEN],
            has_key: false,
            has_preshared_key: false,
        }
    }
}

impl<'a> SymmetricStateType for SymmetricState<'a> {

    fn cipher_name(&self, out : &mut [u8]) -> usize {
        self.cipherstate.name(out)
    }

    fn hash_name(&self, out : &mut [u8]) -> usize {
        self.hasher.name(out)
    }

    fn initialize(&mut self, handshake_name: &[u8]) {
        if handshake_name.len() <= self.hasher.hash_len() {
            self.h = [0u8; MAXHASHLEN];
            copy_memory(handshake_name, &mut self.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name); 
            self.hasher.result(&mut self.h);
        }
        copy_memory(&self.h, &mut self.ck);
        self.has_key = false;
        self.has_preshared_key = false;
    }

    fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.cipherstate.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.has_key = true;
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.h);
    }

    fn mix_preshared_key(&mut self, psk: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.has_preshared_key = true;
    }

    fn has_key(&self) -> bool {
       self.has_key
    }

    fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let hash_len = self.hasher.hash_len();
        let output_len:usize;
        if self.has_key {
            self.cipherstate.encrypt_ad(&self.h[..hash_len], plaintext, out);
            output_len = plaintext.len() + TAGLEN;
        }
        else {
            copy_memory(plaintext, out);
            output_len = plaintext.len();
        }
        self.mix_hash(&out[..output_len]);
        output_len
    }

    fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        let hash_len = self.hasher.hash_len();
        if self.has_key {
            if !self.cipherstate.decrypt_ad(&self.h[..hash_len], data, out) { 
                return false; 
            }
        }
        else {
            copy_memory(data, out);
        }
        self.mix_hash(data);
        true
    }

    fn split(&mut self, child1: &mut CipherStateType, child2: &mut CipherStateType) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], &[0u8; 0], 
                         &mut hkdf_output.0, 
                         &mut hkdf_output.1);
        child1.set(&hkdf_output.0[..CIPHERKEYLEN], 0);
        child2.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
    }

}
