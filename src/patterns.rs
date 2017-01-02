use std::str::FromStr;
use std::fmt;

#[derive(Copy, Clone, Debug)]
pub enum Token {E, S, Dhee, Dhes, Dhse, Dhss}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakePattern {N, X, K, NN, NK, NX, XN, XK, XX, XR, KN, KK, KX, IN, IK, IX, XXfallback}

impl HandshakePattern {

    pub fn is_oneway(&self) -> bool {
        match *self {
            N | X | K => true,
            _ => false
        }
    }

    // XXX double check
    pub fn needs_local_static_key(&self, initiator: bool) -> bool {
        if initiator {
            match *self {
                X | N | K | NN | NK | NX => false,
                _ => true
            }
        } else {
            match *self {
                N | NN | XN | KN | IN => false,
                _ => true
            }
        }
    }

    pub fn need_known_remote_pubkey(&self, initiator: bool) -> bool {
        if initiator {
            match *self {
                NK | XK | KK | IK => true,
                _ => false
            }
        } else {
            match *self {
                K | KN | KK | KX => true,
                _ => false,
            }
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

// NOTE: this can probably be made much shorter with the derived
// Debug trait, but I'm keeping this explicit now.
impl fmt::Display for HandshakePattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::HandshakePattern::*;
        write!(f, "{}", match *self {
            N => "N",
            X => "X",
            K => "K",
            NN => "NN",
            NK => "NK",
            NX => "NX",
            XN => "XN",
            XK => "XK",
            XX => "XX",
            XR => "XR",
            KN => "KN",
            KK => "KK",
            KX => "KX",
            IN => "IN",
            IK => "IK",
            IX => "IX",
            XXfallback => "XXfallback",
        })
    }
}

pub struct HandshakeTokens {
    pub name: String,
    pub premsg_pattern_i: Vec<Token>,
    pub premsg_pattern_r: Vec<Token>,
    pub msg_patterns: Vec<Vec<Token>>,
}

use self::Token::*;
use self::HandshakePattern::*;

pub fn resolve_handshake_pattern(handshake_pattern: HandshakePattern) -> HandshakeTokens {
    let (premsg_pattern_i, premsg_pattern_r, msg_patterns) = match handshake_pattern {
        N  => (
            vec![],
            vec![S],
            vec![vec![E, Dhes]]
        ),
        K  => (
            vec![S],
            vec![S],
            vec![vec![E, Dhes, Dhss]]
        ),
        X  => (
            vec![],
            vec![S],
            vec![vec![E, Dhes, S, Dhss]]
        ),
        NN => (
            vec![],
            vec![],
            vec![vec![E], vec![E, Dhee]]
        ),
        NK => (
            vec![],
            vec![S],
            vec![vec![E, Dhes], vec![E, Dhee]]
        ),
        NX => (
            vec![],
            vec![],
            vec![vec![E], vec![E, Dhee, S, Dhse]]
        ),
        XN => (
            vec![],
            vec![],
            vec![vec![E], vec![E, Dhee], vec![S, Dhse]]
        ),
        XK => (
            vec![],
            vec![S],
            vec![vec![E, Dhes], vec![E, Dhee], vec![S, Dhse]]
        ),
        XX => (
            vec![],
            vec![],
            vec![vec![E], vec![E, Dhee, S, Dhse], vec![S, Dhse]],
        ),
        XR => (
            vec![],
            vec![],
            vec![vec![E], vec![E, Dhee], vec![S, Dhse], vec![S, Dhse]],
        ),
        KN => (
            vec![S],
            vec![],
            vec![vec![E], vec![E, Dhee, Dhes]],
        ),
        KK => (
            vec![S],
            vec![S],
            vec![vec![E, Dhes, Dhss], vec![E, Dhee, Dhes]],
        ),
        KX => (
            vec![S],
            vec![],
            vec![vec![E], vec![E, Dhee, Dhes, S, Dhse]],
        ),
        IN => (
            vec![],
            vec![],
            vec![vec![E, S], vec![E, Dhee, Dhes]],
        ),
        IK => (
            vec![],
            vec![S],
            vec![vec![E, Dhes, S, Dhss], vec![E, Dhee, Dhes]],
        ),
        IX => (
            vec![],
            vec![],
            vec![vec![E, S], vec![E, Dhee, Dhes, S, Dhse]],
        ),
        XXfallback => (
            vec![],
            vec![E],
            vec![vec![E, Dhee, S, Dhse], vec![S, Dhse]],
        )
    };

    HandshakeTokens {
        name: handshake_pattern.to_string(),
        premsg_pattern_i: premsg_pattern_i,
        premsg_pattern_r: premsg_pattern_r,
        msg_patterns: msg_patterns,
    }
}
