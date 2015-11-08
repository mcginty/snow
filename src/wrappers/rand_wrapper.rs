extern crate rand;

use self::rand::{OsRng, Rng};
use crypto_stuff::*;

pub struct RandomOs {
    rng : OsRng
}

impl Random for RandomOs {

    fn new() -> RandomOs {
        RandomOs {rng: OsRng::new().unwrap()}
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out); 
    }

}
