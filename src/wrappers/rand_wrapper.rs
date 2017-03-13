extern crate rand;

use self::rand::{OsRng, Rng};
use types::*;

pub struct RandomOs {
    rng : OsRng
}

impl Default for RandomOs {
    fn default() -> RandomOs {
        RandomOs {rng: OsRng::new().unwrap()}
    }
}

impl Random for RandomOs {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out); 
    }
}
