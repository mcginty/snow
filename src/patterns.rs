use std::str::FromStr;

#[derive(Copy, Clone)]
pub enum Token {E, S, Dhee, Dhes, Dhse, Dhss, Empty}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakePattern {N, X, K, NN, NK, NX, XN, XK, XX, XR, KN, KK, KX, IN, IK, IX, XXfallback}

impl HandshakePattern {

    // XXX double check
    pub fn needs_local_key(p: HandshakePattern) -> bool {
        match p {
            N | NN | NK | NX => false,
            _ => true
        }
    }

    // XXX double check
    pub fn needs_known_remote_key(p: HandshakePattern) -> bool {
        match p {
            N | X | K | NN | XN | KN | IN => false,
            _ => true
        }
    }
}

impl FromStr for HandshakePattern {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::HandshakePattern::*;
        match s {
            "N" => Ok(N),
            "X" => Ok(X),
            "K" => Ok(K),
            "NN" => Ok(NN),
            "NK" => Ok(NK),
            "NX" => Ok(NX),
            "XN" => Ok(XN),
            "XK" => Ok(XK),
            "XX" => Ok(XX),
            "XR" => Ok(XR),
            "KN" => Ok(KN),
            "KK" => Ok(KK),
            "KX" => Ok(KX),
            "IN" => Ok(IN),
            "IK" => Ok(IK),
            "IX" => Ok(IX),
            "XXfallback" => Ok(XXfallback),
            _    => Err("handshake not recognized")
        }
    }
}

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
