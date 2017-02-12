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

impl HandshakePattern {
    fn as_str(&self) -> &'static str {
        use self::HandshakePattern::*;
        match *self {
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
        }
    }
}

pub struct HandshakeTokens {
    pub name: &'static str,
    pub premsg_pattern_i: &'static [Token],
    pub premsg_pattern_r: &'static [Token],
    pub msg_patterns: &'static [&'static [Token]],
}

use self::Token::*;
use self::HandshakePattern::*;

type Patterns = (&'static [Token], &'static [Token], &'static [&'static [Token]]);

pub fn resolve_handshake_pattern(handshake_pattern: HandshakePattern) -> HandshakeTokens {
    let patterns: Patterns = match handshake_pattern {
        N  => (
            static_slice![Token: ],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes]]
        ),
        K  => (
            static_slice![Token: S],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes, Dhss]]
        ),
        X  => (
            static_slice![Token: ],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes, S, Dhss]]
        ),
        NN => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee]]
        ),
        NK => (
            static_slice![Token: ],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes], &[E, Dhee]]
        ),
        NX => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee, S, Dhse]]
        ),
        XN => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee], &[S, Dhse]]
        ),
        XK => (
            static_slice![Token: ],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes], &[E, Dhee], &[S, Dhse]]
        ),
        XX => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee, S, Dhse], &[S, Dhse]],
        ),
        XR => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee], &[S, Dhse], &[S, Dhse]],
        ),
        KN => (
            static_slice![Token: S],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee, Dhes]],
        ),
        KK => (
            static_slice![Token: S],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes, Dhss], &[E, Dhee, Dhes]],
        ),
        KX => (
            static_slice![Token: S],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E], &[E, Dhee, Dhes, S, Dhse]],
        ),
        IN => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E, S], &[E, Dhee, Dhes]],
        ),
        IK => (
            static_slice![Token: ],
            static_slice![Token: S],
            static_slice![&'static [Token]: &[E, Dhes, S, Dhss], &[E, Dhee, Dhes]],
        ),
        IX => (
            static_slice![Token: ],
            static_slice![Token: ],
            static_slice![&'static [Token]: &[E, S], &[E, Dhee, Dhes, S, Dhse]],
        ),
        XXfallback => (
            static_slice![Token: ],
            static_slice![Token: E],
            static_slice![&'static [Token]: &[E, Dhee, S, Dhse], &[S, Dhse]],
        )
    };

    HandshakeTokens {
        name: handshake_pattern.as_str(),
        premsg_pattern_i: patterns.0,
        premsg_pattern_r: patterns.1,
        msg_patterns: patterns.2,
    }
}
