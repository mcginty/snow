
use handshake::{Token, HandshakePattern};
use handshake::Token::*;
use crypto_stuff::{copy_memory};

fn copy_tokens(input: &[Token], out: &mut [Token]) {
    for count in 0..input.len() {out[count] = input[count];}
}

pub struct NoiseN;
pub struct NoiseK;
pub struct NoiseX;

pub struct NoiseNN;
pub struct NoiseNK;
pub struct NoiseNX;

pub struct NoiseXN;
pub struct NoiseXK;
pub struct NoiseXX;
pub struct NoiseXR;

pub struct NoiseKN;
pub struct NoiseKK;
pub struct NoiseKX;

pub struct NoiseIN;
pub struct NoiseIK;
pub struct NoiseIX;

pub struct NoiseXXfallback;

impl HandshakePattern for NoiseN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("N".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token],
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
    }
}

impl HandshakePattern for NoiseK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("K".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
    }
}

impl HandshakePattern for NoiseX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("X".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
    }
}

impl HandshakePattern for NoiseNN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("NN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseNK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("NK".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseNX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("NX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseXN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("XN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
    }
}

impl HandshakePattern for NoiseXK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("XK".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
    }
}

impl HandshakePattern for NoiseXX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("XX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
    }
}

impl HandshakePattern for NoiseXR {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("XR".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[3]);
    }
}

impl HandshakePattern for NoiseKN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("KN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseKK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("KK".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseKX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("KX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseIN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("IN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E, S], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseIK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("IK".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S], premsg_pattern_r);

        copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseIX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("IX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[E, S], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseXXfallback {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("XXfallback".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[E], premsg_pattern_r);

        copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[0]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[1]);
    }
}
