
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
                            name: &mut String,
                            premsg_pattern_i: &mut [Token],
                            premsg_pattern_r: &mut [Token], 
                            msg_patterns: &mut [[Token; 10]; 10]) {
    match handshake_pattern {
        N => { 
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            name.push_str("N");
        },

        K => { 
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
            name.push_str("K");
        },

        X => { 
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
            name.push_str("X");
        },

        NN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            name.push_str("NN");
        },

        NK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            name.push_str("NK");
        },

        NX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
            name.push_str("NX");
        },

        XN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            name.push_str("XN");
        },

        XK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            name.push_str("XK");
        },

        XX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            name.push_str("XX");
        },

        XR => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee], &mut msg_patterns[1]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[2]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[3]);
            name.push_str("XR");
        },

        KN => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            name.push_str("KN");
        }

        KK => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, Dhss], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            name.push_str("KK");
        }

        KX => {
            copy_tokens(&[S], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
            name.push_str("KX");
        }

        IN => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E, S], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            name.push_str("IN");
        }

        IK => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[S], premsg_pattern_r);
            copy_tokens(&[E, Dhes, S, Dhss], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes], &mut msg_patterns[1]);
            name.push_str("IK");
        }

        IX => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[], premsg_pattern_r);
            copy_tokens(&[E, S], &mut msg_patterns[0]);
            copy_tokens(&[E, Dhee, Dhes, S, Dhse], &mut msg_patterns[1]);
            name.push_str("IX");
        }

        XXfallback => {
            copy_tokens(&[], premsg_pattern_i);
            copy_tokens(&[E], premsg_pattern_r);
            copy_tokens(&[E, Dhee, S, Dhse], &mut msg_patterns[0]);
            copy_tokens(&[S, Dhse], &mut msg_patterns[1]);
            name.push_str("XXfallback");
        }
    }
}
