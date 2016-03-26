
use utils::*;

#[derive(Copy, Clone)]
pub enum Token {E, S, Dhee, Dhes, Dhse, Dhss, Empty}

#[derive(Copy, Clone)]
pub enum HandshakePattern {N, X, K, NN, NK, NX, XN, XK, XX, XR, KN, KK, KX, IN, IK, IX, XXfallback}

use self::Token::*;
use self::HandshakePattern::*;

fn copy_tokens(input: &[Token], out: &mut [Token]) {
    for count in 0..input.len() {out[count] = input[count];}
}

pub fn resolve_handshake_pattern(
                            handshake_pattern: HandshakePattern,
                            name: &mut [u8], 
                            premsg_pattern_i: &mut [Token],
                            premsg_pattern_r: &mut [Token], 
                            msg_patterns: &mut [[Token; 10]; 10]) -> usize {
    match handshake_pattern {
        N => { 
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            copy_memory("N".as_bytes(), name)
        },

        K => { 
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
            copy_memory("K".as_bytes(), name)
        },

        X => { 
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
            copy_memory("X".as_bytes(), name)
        },

        NN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_memory("NN".as_bytes(), name)
        },

        NK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_memory("NK".as_bytes(), name)
        },

        NX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
            copy_memory("NX".as_bytes(), name)
        },

        XN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            copy_memory("XN".as_bytes(), name)
        },

        XK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            copy_memory("XK".as_bytes(), name)
        },

        XX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            copy_memory("XX".as_bytes(), name)
        },

        XR => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[3]);
            copy_memory("XR".as_bytes(), name)
        },

        KN => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            copy_memory("KN".as_bytes(), name)
        }

        KK => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            copy_memory("KK".as_bytes(), name)
        }

        KX => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
            copy_memory("KX".as_bytes(), name)
        }

        IN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E, S], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            copy_memory("IN".as_bytes(), name)
        }

        IK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            copy_memory("IK".as_bytes(), name)
        }

        IX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E, S], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
            copy_memory("IX".as_bytes(), name)
        }

        XXfallback => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[E], premsg_pattern_r);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[0]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[1]);
            copy_memory("XXfallback".as_bytes(), name)
        }
    }
}
