#[cfg(feature = "nightly")] use std::convert::{TryFrom};
#[cfg(not(feature = "nightly"))] use utils::{TryFrom};
use error::{SnowError, PatternProblem};
use std::str::FromStr;
use smallvec::SmallVec;

macro_rules! message_vec {
    ($($item:expr),*) => ({
        let token_groups: &[&[Token]] = &[$($item),*];
        let mut vec: MessagePatterns = SmallVec::new();
        for group in token_groups {
            let mut inner: SmallVec<[_; 10]> = SmallVec::new();
            inner.extend_from_slice(group);
            vec.push(inner);
        }
        vec
    });
}

/// The tokens which describe message patterns.
///
/// See: http://noiseprotocol.org/noise.html#handshake-patterns
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum Token { E, S, Dhee, Dhes, Dhse, Dhss, Psk(u8) }

/// One of the patterns as defined in the
/// [Handshake Pattern](http://noiseprotocol.org/noise.html#handshake-patterns) section
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakePattern { N, X, K, NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX }

impl HandshakePattern {
    /// If the protocol is one-way only
    ///
    /// See: http://noiseprotocol.org/noise.html#one-way-patterns
    pub fn is_oneway(self) -> bool {
        match self {
            N | X | K => true,
            _ => false
        }
    }

    /// Whether this pattern requires a long-term static key.
    pub fn needs_local_static_key(self, initiator: bool) -> bool {
        if initiator {
            match self {
                N | NN | NK | NX => false,
                _ => true
            }
        } else {
            match self {
                NN | XN | KN | IN => false,
                _ => true
            }
        }
    }

    /// Whether this pattern demands a remote public key pre-message.
    pub fn need_known_remote_pubkey(self, initiator: bool) -> bool {
        if initiator {
            match self {
                N | K | X | NK | XK | KK | IK => true,
                _ => false
            }
        } else {
            match self {
                K | KN | KK | KX => true,
                _ => false,
            }
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakeModifier {
    /// Insert a PSK to mix at the associated position
    Psk(u8),

    /// Modify the base pattern to its "fallback" form
    Fallback
}

impl FromStr for HandshakeModifier {
    type Err = SnowError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("psk") {
            Ok(HandshakeModifier::Psk((&s[3..])
                .parse()
                .map_err(|_| PatternProblem::InvalidPsk)?))
        } else if s == "fallback" {
            Ok(HandshakeModifier::Fallback)
        } else {
            bail!(PatternProblem::UnsupportedModifier);
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeModifierList {
    pub list: SmallVec<[HandshakeModifier; 10]>
}

impl FromStr for HandshakeModifierList {
    type Err = SnowError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(HandshakeModifierList{ list: SmallVec::new() })
        } else {
            let modifier_names = s.split('+');
            let mut modifiers = SmallVec::new();
            for modifier_name in modifier_names {
                modifiers.push(modifier_name.parse()?);
            }
            Ok(HandshakeModifierList{ list: modifiers })
        }
    }
}

/// The pattern/modifier combination choice (no primitives specified)
/// for a full noise protocol definition.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeChoice {
    /// The base pattern itself
    pub pattern: HandshakePattern,

    /// The modifier(s) requested for the base pattern
    pub modifiers: HandshakeModifierList,
}

impl HandshakeChoice {
    /// Whether the handshake choice includes one or more PSK modifiers.
    pub fn is_psk(&self) -> bool {
        for modifier in &self.modifiers.list {
            if let HandshakeModifier::Psk(_) = *modifier {
                return true;
            }
        }
        false
    }

    /// Whether the handshake choice includes the fallback modifier.
    pub fn is_fallback(&self) -> bool {
        for modifier in &self.modifiers.list {
            if HandshakeModifier::Fallback == *modifier {
                return true;
            }
        }
        false
    }
}

impl FromStr for HandshakeChoice {
    type Err = SnowError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder);
        if s.len() > 1 {
            if let Ok(p) = (&s[..2]).parse() {
                pattern = p;
                remainder = &s[2..];
            } else {
                pattern = (&s[..1]).parse()?;
                remainder = &s[1..];
            }
        } else {
            pattern = (&s[..1]).parse()?;
            remainder = &s[1..];
        }

        Ok(HandshakeChoice {
            pattern,
            modifiers: remainder.parse()?
        })
    }
}

impl FromStr for HandshakePattern {
    type Err = SnowError;
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
            "KN" => Ok(KN),
            "KK" => Ok(KK),
            "KX" => Ok(KX),
            "IN" => Ok(IN),
            "IK" => Ok(IK),
            "IX" => Ok(IX),
            _    => bail!(PatternProblem::UnsupportedHandshakeType)
        }
    }
}

impl HandshakePattern {
    /// The equivalent of the `ToString` trait, but for `&'static str`.
    pub fn as_str(self) -> &'static str {
        use self::HandshakePattern::*;
        match self {
            N => "N",
            X => "X",
            K => "K",
            NN => "NN",
            NK => "NK",
            NX => "NX",
            XN => "XN",
            XK => "XK",
            XX => "XX",
            KN => "KN",
            KK => "KK",
            KX => "KX",
            IN => "IN",
            IK => "IK",
            IX => "IX",
        }
    }
}

type PremessagePatterns = &'static [Token];
pub(crate) type MessagePatterns = SmallVec<[SmallVec<[Token; 10]>; 10]>;

/// The defined token patterns for a given handshake.
///
/// See: http://noiseprotocol.org/noise.html#handshake-patterns
#[derive(Debug)]
pub(crate) struct HandshakeTokens {
    pub premsg_pattern_i: PremessagePatterns,
    pub premsg_pattern_r: PremessagePatterns,
    pub msg_patterns: MessagePatterns,
}

use self::Token::*;
use self::HandshakePattern::*;

type Patterns = (PremessagePatterns, PremessagePatterns, MessagePatterns);

impl<'a> TryFrom<&'a HandshakeChoice> for HandshakeTokens {
    type Error = SnowError;

    fn try_from(handshake: &'a HandshakeChoice) -> Result<Self, Self::Error> {
        let mut patterns: Patterns = match handshake.pattern {
            N  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes]]
            ),
            K  => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dhes, Dhss]]
            ),
            X  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes, S, Dhss]]
            ),
            NN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee]]
            ),
            NK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee]]
            ),
            NX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse]]
            ),
            XN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee], &[S, Dhse]]
            ),
            XK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee], &[S, Dhse]]
            ),
            XX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse], &[S, Dhse]],
            ),
            KN => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, Dhes]],
            ),
            KK => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dhes, Dhss], &[E, Dhee, Dhes]],
            ),
            KX => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, Dhes, S, Dhse]],
            ),
            IN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, Dhes]],
            ),
            IK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes, S, Dhss], &[E, Dhee, Dhes]],
            ),
            IX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, Dhes, S, Dhse]],
            ),
        };

        for modifier in handshake.modifiers.list.iter() {
            if let HandshakeModifier::Psk(n) = modifier {
                match n {
                    0 => { patterns.2[0].insert(0, Token::Psk(*n)); },
                    _ => {
                        let i = (*n as usize) - 1;
                        patterns.2[i].push(Token::Psk(*n));
                    }
                }
            }
        }

        Ok(HandshakeTokens {
            premsg_pattern_i: patterns.0,
            premsg_pattern_r: patterns.1,
            msg_patterns: patterns.2,
        })
    }
}

