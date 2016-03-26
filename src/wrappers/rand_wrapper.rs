extern crate rand;

use self::rand::{OsRng, Rng};
use crypto_types::*;

pub struct RandomOs {
    rng : OsRng
}

impl RandomOs {
    pub fn new() -> RandomOs {
        RandomOs {rng: OsRng::new().unwrap()}
    }
}

impl RandomType for RandomOs {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out); 
    }
}
