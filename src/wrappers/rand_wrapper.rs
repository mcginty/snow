extern crate rand;

use self::rand::{OsRng, Rng};
use crypto_stuff::*;

pub struct OsRandom {
    rng : OsRng
}

impl Random for OsRandom {

    fn new() -> OsRandom {
        OsRandom {rng: OsRng::new().unwrap()}
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out); 
    }

}
