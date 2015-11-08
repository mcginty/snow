
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
pub struct NoiseNE;
pub struct NoiseNX;

pub struct NoiseXN;
pub struct NoiseXK;
pub struct NoiseXE;
pub struct NoiseXX;

pub struct NoiseKN;
pub struct NoiseKK;
pub struct NoiseKE;
pub struct NoiseKX;

pub struct NoiseIN;
pub struct NoiseIK;
pub struct NoiseIE;
pub struct NoiseIX;

impl HandshakePattern for NoiseN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_N".as_bytes(), out)
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
        copy_memory("Noise_K".as_bytes(), out)
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
        copy_memory("Noise_K".as_bytes(), out)
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
        copy_memory("Noise_NN".as_bytes(), out)
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
        copy_memory("Noise_NK".as_bytes(), out)
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

impl HandshakePattern for NoiseNE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S, E], premsg_pattern_r);

        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseNX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NX".as_bytes(), out)
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
        copy_memory("Noise_XN".as_bytes(), out)
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
        copy_memory("Noise_XK".as_bytes(), out)
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

impl HandshakePattern for NoiseXE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XE".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S, E], premsg_pattern_r);

        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
    }
}

impl HandshakePattern for NoiseXX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
        copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
    }
}

impl HandshakePattern for NoiseKN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KN".as_bytes(), out)
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
        copy_memory("Noise_KK".as_bytes(), out)
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

impl HandshakePattern for NoiseKE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("noise_ke".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], premsg_pattern_i);
        copy_tokens(&[S, E], premsg_pattern_r);

        copy_tokens(&[E, Dhee, Dhes, Dhse], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseKX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KX".as_bytes(), out)
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
        copy_memory("Noise_IN".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[S, E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseIK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IK".as_bytes(), out)
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

impl HandshakePattern for NoiseIE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IE".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[S, E], premsg_pattern_r);

        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
    }
}

impl HandshakePattern for NoiseIX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IX".as_bytes(), out)
    }

    fn get(premsg_pattern_i: &mut [Token], 
           premsg_pattern_r: &mut [Token], 
           msg_patterns: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], premsg_pattern_i);
        copy_tokens(&[], premsg_pattern_r);

        copy_tokens(&[S, E], &mut msg_patterns[0]);
        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
    }
}
