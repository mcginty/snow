
use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;

pub struct HandshakeCryptoOwner<R: RandomType + Default, 
                          D: DhType + Default, 
                          C: CipherType + Default, 
                          H: HashType + Default> {
    pub rng: R,
    pub cipherstate: CipherState<C>,
    pub hasher: H,
    pub s: D,
    pub e: D,
    pub rs: [u8; MAXDHLEN],
    pub re: [u8; MAXDHLEN],
    pub has_s: bool, 
    pub has_e: bool, 
    pub has_rs: bool, 
    pub has_re: bool,
}

impl<R: RandomType + Default, 
     D: DhType + Default, 
     C: CipherType + Default, 
     H: HashType + Default> Default for HandshakeCryptoOwner<R, D, C, H> {

    fn default() -> HandshakeCryptoOwner<R, D, C, H> {
        HandshakeCryptoOwner{
            rng : Default::default(),
            cipherstate: Default::default(),
            hasher: Default::default(),
            s: Default::default(),
            e: Default::default(),
            rs: [0u8; MAXDHLEN],
            re: [0u8; MAXDHLEN],
            has_s: false,
            has_e: false,
            has_rs: false,
            has_re: false,
        }
    }
}

impl<R: RandomType + Default, 
     D: DhType + Default, 
     C: CipherType + Default, 
     H: HashType + Default> HandshakeCryptoOwner<R, D, C, H> {

    pub fn new() -> HandshakeCryptoOwner<R, D, C, H> {
        Default::default()
    }

    pub fn clear_dh_flags(&mut self) {
        self.has_s = false;
        self.has_e = false;
        self.has_rs = false;
        self.has_re = false;
    }

    pub fn set_s(&mut self, s: D) {
        self.s = s;
        self.has_s = true;
    }

    pub fn set_e(&mut self, e: D) {
        self.e = e;
        self.has_e = true;
    }

    pub fn set_rs(&mut self, rs: &[u8]) {
        copy_memory(rs, &mut self.rs);
        self.has_rs = true;
    }

    pub fn set_re(&mut self, re: &[u8]) {
        copy_memory(re, &mut self.re);
        self.has_re = true;
    }
 }

