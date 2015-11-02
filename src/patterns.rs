
use handshake::{Token, Pattern};
use handshake::Token::*;
use crypto_stuff::{copy_memory};

fn copy_tokens(input: &[Token], out: &mut [Token]) {
    for count in 0..input.len() {out[count] = input[count];}
}



pub struct NoiseXX;

impl Pattern for NoiseXX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XX".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => copy_tokens(&[E], out),
            1 => copy_tokens(&[E, Dhee, S, Dhse], out),
            2 => { copy_tokens(&[S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}
