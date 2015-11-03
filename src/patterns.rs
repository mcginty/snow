
use handshake::{Token, Pattern};
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

impl Pattern for NoiseN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_N".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhes], &mut messages[0]);
    }
}

impl Pattern for NoiseK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_K".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[S], pre_initiator);

        copy_tokens(&[E, Dhes, Dhss], &mut messages[0]);
    }
}

impl Pattern for NoiseX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_K".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhes, S, Dhss], &mut messages[0]);
    }
}

impl Pattern for NoiseNN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
    }
}

impl Pattern for NoiseNK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NK".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhes], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
    }
}

impl Pattern for NoiseNE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S, E], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhee, Dhes], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
    }
}

impl Pattern for NoiseNX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NX".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee, S, Dhse], &mut messages[1]);
    }
}

impl Pattern for NoiseXN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XN".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
        copy_tokens(&[S, Dhse], &mut messages[1]);
    }
}

impl Pattern for NoiseXK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XK".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhes], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
        copy_tokens(&[S, Dhse], &mut messages[1]);
    }
}

impl Pattern for NoiseXE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XE".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S, E], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhee, Dhes], &mut messages[0]);
        copy_tokens(&[E, Dhee], &mut messages[1]);
        copy_tokens(&[S, Dhse], &mut messages[1]);
    }
}

impl Pattern for NoiseXX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XX".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee, S, Dhse], &mut messages[1]);
        copy_tokens(&[S, Dhse], &mut messages[2]);
    }
}

impl Pattern for NoiseKN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KN".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[S], pre_initiator);

        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseKK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KK".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[S], pre_initiator);

        copy_tokens(&[E, Dhes, Dhss], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseKE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("noise_ke".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S, E], pre_responder);
        copy_tokens(&[S], pre_initiator);

        copy_tokens(&[E, Dhee, Dhes, Dhse], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseKX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KX".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[S], pre_initiator);

        copy_tokens(&[E], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut messages[1]);
    }
}

impl Pattern for NoiseIN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IN".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[S, E], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseIK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IK".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhes, S, Dhss], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseIE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IE".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[S, E], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes], &mut messages[1]);
    }
}

impl Pattern for NoiseIX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IX".as_bytes(), out)
    }

    fn pattern(pre_responder: &mut [Token], 
               pre_initiator: &mut [Token], 
               messages: &mut [[Token; 8]; 5]) {
        copy_tokens(&[], pre_responder);
        copy_tokens(&[], pre_initiator);

        copy_tokens(&[S, E], &mut messages[0]);
        copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut messages[1]);
    }
}

/*







impl Pattern for NoiseK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_K".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes, Dhss], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_X".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes, S, Dhss], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseNN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseNK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes], out) },
            1 => { copy_tokens(&[E, Dhee], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseNE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, E], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhee, Dhes], out) },
            1 => { copy_tokens(&[E, Dhee], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseNX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_NX".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee, S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseXN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee], out) },
            2 => { copy_tokens(&[S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseXK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XK".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes], out) },
            1 => { copy_tokens(&[E, Dhee], out) },
            2 => { copy_tokens(&[S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseXE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XE".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, E], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhee, Dhes], out) },
            1 => { copy_tokens(&[E, Dhee], out) },
            2 => { copy_tokens(&[S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseXX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_XX".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee, S, Dhse], out) },
            2 => { copy_tokens(&[S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseKN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseKK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KK".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes, Dhss], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseKE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KE".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhee, Dhes, Dhse], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseKX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_KX".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes, S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseIN {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[S, E], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseIK {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IN".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhes, S, Dhss], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseIE {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IE".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[S, E], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[E, Dhee, Dhes, S, Dhse], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

impl Pattern for NoiseIX {
    fn name(out : &mut [u8]) -> usize { 
        copy_memory("Noise_IX".as_bytes(), out)
    }

    fn premessages(out: &mut [Token]) {
        copy_tokens(&[], out);
    }

    fn next_descriptor(index: u8, out: &mut [Token]) -> bool {
        match index {
            0 => { copy_tokens(&[S, E], out) },
            1 => { copy_tokens(&[E, Dhee, Dhes, S, Dhse], out); return true; }
            _ => unreachable!()
        }; 
        false
    }
}

*/
