
use handshake::{Token};
use handshake::Token::*;
use crypto_stuff::{copy_memory};

fn copy_tokens(input: &[Token], out: &mut [Token]) {
    for count in 0..input.len() {out[count] = input[count];}
}

pub trait Pattern {
    fn name(s : &mut [u8]);
    fn premessages(out: &mut [Token]);
    fn pattern(index: u8, out: &mut [Token]);
}

pub struct NoiseXX;

impl Pattern for NoiseXX {
    fn name(s : &mut [u8]) { copy_memory("Noise_XX".as_bytes(), s);}

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn pattern(index: u8, out: &mut [Token]) {
        match index {
            0 => copy_tokens(&[E], out),
            1 => copy_tokens(&[E, Dhee, S, Dhse], out),
            2 => copy_tokens(&[S, Dhse], out),
            _ => unreachable!()
        }; 
    }
}
