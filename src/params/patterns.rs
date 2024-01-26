use crate::error::{Error, PatternProblem};
use std::{convert::TryFrom, str::FromStr};

/// A small helper macro that behaves similar to the `vec![]` standard macro,
/// except it allocates a bit extra to avoid resizing.
macro_rules! message_vec {
    ($($item:expr),*) => ({
        let token_groups: &[&[Token]] = &[$($item),*];
        let mut vec: MessagePatterns = Vec::with_capacity(10);
        for group in token_groups {
            let mut inner = Vec::with_capacity(10);
            inner.extend_from_slice(group);
            vec.push(inner);
        }
        vec
    });
}

/// This macro is specifically a helper to generate the enum of all handshake
/// patterns in a less error-prone way.
///
/// While rust macros can be really difficult to read, it felt too sketchy to hand-
/// write a growing list of str -> enum variant match statements.
macro_rules! pattern_enum {
    // NOTE: see https://danielkeep.github.io/tlborm/book/mbe-macro-rules.html and
    // https://doc.rust-lang.org/rust-by-example/macros.html for a great overview
    // of `macro_rules!`.
    ($name:ident {
        $($variant:ident),* $(,)*
    }) => {
        /// One of the patterns as defined in the
        /// [Handshake Pattern](https://noiseprotocol.org/noise.html#handshake-patterns)
        /// section.
        #[allow(missing_docs)]
        #[derive(Copy, Clone, PartialEq, Debug)]
        pub enum $name {
            $($variant),*,
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use self::$name::*;
                match s {
                    $(
                        stringify!($variant) => Ok($variant)
                    ),
                    *,
                    _    => return Err(PatternProblem::UnsupportedHandshakeType.into())
                }
            }
        }

        impl $name {
            /// The equivalent of the `ToString` trait, but for `&'static str`.
            pub fn as_str(self) -> &'static str {
                use self::$name::*;
                match self {
                    $(
                        $variant => stringify!($variant)
                    ),
                    *
                }
            }
        }

        #[doc(hidden)]
        pub const SUPPORTED_HANDSHAKE_PATTERNS: &'static [$name] = &[$($name::$variant),*];
    }
}

/// The tokens which describe patterns involving DH calculations.
///
/// See: https://noiseprotocol.org/noise.html#handshake-patterns
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum DhToken {
    Ee,
    Es,
    Se,
    Ss,
}

/// The tokens which describe message patterns.
///
/// See: https://noiseprotocol.org/noise.html#handshake-patterns
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum Token {
    E,
    S,
    Dh(DhToken),
    Psk(u8),
    #[cfg(feature = "hfs")]
    E1,
    #[cfg(feature = "hfs")]
    Ekem1,
}

#[cfg(feature = "hfs")]
impl Token {
    fn is_dh(&self) -> bool {
        match *self {
            Dh(_) => true,
            _ => false,
        }
    }
}

// See the documentation in the macro above.
pattern_enum! {
    HandshakePattern {
        // 7.4. One-way handshake patterns
        N, X, K,

        // 7.5. Interactive handshake patterns (fundamental)
        NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX,

        // 7.6. Interactive handshake patterns (deferred)
        NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X,
        KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
    }
}

impl HandshakePattern {
    /// If the protocol is one-way only
    ///
    /// See: https://noiseprotocol.org/noise.html#one-way-handshake-patterns
    pub fn is_oneway(self) -> bool {
        matches!(self, N | X | K)
    }

    /// Whether this pattern requires a long-term static key.
    pub fn needs_local_static_key(self, initiator: bool) -> bool {
        if initiator {
            !matches!(self, N | NN | NK | NX | NK1 | NX1)
        } else {
            !matches!(self, NN | XN | KN | IN | X1N | K1N | I1N)
        }
    }

    /// Whether this pattern demands a remote public key pre-message.
    #[rustfmt::skip]
    pub fn need_known_remote_pubkey(self, initiator: bool) -> bool {
        if initiator {
            matches!(
                self,
                N | K | X | NK | XK | KK | IK | NK1 | X1K | XK1 | X1K1 | K1K | KK1 | K1K1 | I1K | IK1 | I1K1
            )
        } else {
            matches!(
                self,
                K | KN | KK | KX | K1N | K1K | KK1 | K1K1 | K1X | KX1 | K1X1
            )
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakeModifier {
    /// Insert a PSK to mix at the associated position
    Psk(u8),

    /// Modify the base pattern to its "fallback" form
    Fallback,

    #[cfg(feature = "hfs")]
    /// Modify the base pattern to use Hybrid-Forward-Secrecy
    Hfs,
}

impl FromStr for HandshakeModifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s.starts_with("psk") => {
                Ok(HandshakeModifier::Psk(s[3..].parse().map_err(|_| PatternProblem::InvalidPsk)?))
            },
            "fallback" => Ok(HandshakeModifier::Fallback),
            #[cfg(feature = "hfs")]
            "hfs" => Ok(HandshakeModifier::Hfs),
            _ => Err(PatternProblem::UnsupportedModifier.into()),
        }
    }
}

/// Handshake modifiers that will be used during key exchange handshake.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeModifierList {
    /// List of parsed modifiers.
    pub list: Vec<HandshakeModifier>,
}

impl FromStr for HandshakeModifierList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(HandshakeModifierList { list: vec![] })
        } else {
            let modifier_names = s.split('+');
            let mut modifiers = vec![];
            for modifier_name in modifier_names {
                let modifier: HandshakeModifier = modifier_name.parse()?;
                if modifiers.contains(&modifier) {
                    return Err(Error::Pattern(PatternProblem::UnsupportedModifier));
                } else {
                    modifiers.push(modifier);
                }
            }
            Ok(HandshakeModifierList { list: modifiers })
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
        self.modifiers.list.contains(&HandshakeModifier::Fallback)
    }

    /// Whether the handshake choice includes the hfs modifier.
    #[cfg(feature = "hfs")]
    pub fn is_hfs(&self) -> bool {
        self.modifiers.list.contains(&HandshakeModifier::Hfs)
    }

    /// Parse and split a base HandshakePattern from its optional modifiers
    fn parse_pattern_and_modifier(s: &str) -> Result<(HandshakePattern, &str), Error> {
        for i in (1..=4).rev() {
            if s.len() > i - 1 && s.is_char_boundary(i) {
                if let Ok(p) = s[..i].parse() {
                    return Ok((p, &s[i..]));
                }
            }
        }

        Err(PatternProblem::UnsupportedHandshakeType.into())
    }
}

impl FromStr for HandshakeChoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder) = Self::parse_pattern_and_modifier(s)?;
        let modifiers = remainder.parse()?;

        Ok(HandshakeChoice { pattern, modifiers })
    }
}

type PremessagePatterns = &'static [Token];
pub(crate) type MessagePatterns = Vec<Vec<Token>>;

/// The defined token patterns for a given handshake.
///
/// See: https://noiseprotocol.org/noise.html#handshake-patterns
#[derive(Debug)]
pub(crate) struct HandshakeTokens {
    pub premsg_pattern_i: PremessagePatterns,
    pub premsg_pattern_r: PremessagePatterns,
    pub msg_patterns:     MessagePatterns,
}

use self::{DhToken::*, HandshakePattern::*, Token::*};

type Patterns = (PremessagePatterns, PremessagePatterns, MessagePatterns);

impl<'a> TryFrom<&'a HandshakeChoice> for HandshakeTokens {
    type Error = Error;

    #[allow(clippy::cognitive_complexity)]
    fn try_from(handshake: &'a HandshakeChoice) -> Result<Self, Self::Error> {
        // Hfs cannot be combined with one-way handshake patterns
        #[cfg(feature = "hfs")]
        check_hfs_and_oneway_conflict(handshake)?;

        #[rustfmt::skip]
        let mut patterns: Patterns = match handshake.pattern {
            N  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es)]]
            ),
            K  => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es), Dh(Ss)]]
            ),
            X  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es), S, Dh(Ss)]]
            ),
            NN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee)]]
            ),
            NK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es)], &[E, Dh(Ee)]]
            ),
            NX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S, Dh(Es)]]
            ),
            XN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee)], &[S, Dh(Se)]]
            ),
            XK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es)], &[E, Dh(Ee)], &[S, Dh(Se)]]
            ),
            XX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S, Dh(Es)], &[S, Dh(Se)]],
            ),
            KN => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), Dh(Se)]],
            ),
            KK => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es), Dh(Ss)], &[E, Dh(Ee), Dh(Se)]],
            ),
            KX => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), Dh(Se), S, Dh(Es)]],
            ),
            IN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee), Dh(Se)]],
            ),
            IK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es), S, Dh(Ss)], &[E, Dh(Ee), Dh(Se)]],
            ),
            IX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee), Dh(Se), S, Dh(Es)]],
            ),
            NK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dh(Ee), Dh(Es)]],
            ),
            NX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S], &[Dh(Es)]]
            ),
            X1N => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee)], &[S], &[Dh(Se)]]
            ),
            X1K => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es)], &[E, Dh(Ee)], &[S], &[Dh(Se)]]
            ),
            XK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dh(Ee), Dh(Es)], &[S, Dh(Se)]]
            ),
            X1K1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dh(Ee), Dh(Es)], &[S], &[Dh(Se)]]
            ),
            X1X => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S, Dh(Es)], &[S], &[Dh(Se)]],
            ),
            XX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S], &[Dh(Es), S, Dh(Se)]],
            ),
            X1X1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S], &[Dh(Es), S], &[Dh(Se)]],
            ),
            K1N => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee)], &[Dh(Se)]],
            ),
            K1K => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es)], &[E, Dh(Ee)], &[Dh(Se)]],
            ),
            KK1 => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dh(Ee), Dh(Se), Dh(Es)]],
            ),
            K1K1 => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dh(Ee), Dh(Es)], &[Dh(Se)]],
            ),
            K1X => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S, Dh(Es)], &[Dh(Se)]],
            ),
            KX1 => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), Dh(Se), S], &[Dh(Es)]],
            ),
            K1X1 => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dh(Ee), S], &[Dh(Se), Dh(Es)]],
            ),
            I1N => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee)], &[Dh(Se)]],
            ),
            I1K => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dh(Es), S], &[E, Dh(Ee)], &[Dh(Se)]],
            ),
            IK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, S], &[E, Dh(Ee), Dh(Se), Dh(Es)]],
            ),
            I1K1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, S], &[E, Dh(Ee), Dh(Es)], &[Dh(Se)]],
            ),
            I1X => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee), S, Dh(Es)], &[Dh(Se)]],
            ),
            IX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee), Dh(Se), S], &[Dh(Es)]],
            ),
            I1X1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dh(Ee), S], &[Dh(Se), Dh(Es)]],
            ),
        };

        for modifier in handshake.modifiers.list.iter() {
            match modifier {
                HandshakeModifier::Psk(n) => apply_psk_modifier(&mut patterns, *n)?,
                #[cfg(feature = "hfs")]
                HandshakeModifier::Hfs => apply_hfs_modifier(&mut patterns),
                _ => return Err(PatternProblem::UnsupportedModifier.into()),
            }
        }

        Ok(HandshakeTokens {
            premsg_pattern_i: patterns.0,
            premsg_pattern_r: patterns.1,
            msg_patterns:     patterns.2,
        })
    }
}

#[cfg(feature = "hfs")]
/// Check that this handshake is not HFS *and* one-way.
///
/// Usage of HFS in conjuction with a oneway pattern is invalid. This function returns an error
/// if `handshake` is invalid because of this. Otherwise it will return `()`.
fn check_hfs_and_oneway_conflict(handshake: &HandshakeChoice) -> Result<(), Error> {
    if handshake.is_hfs() && handshake.pattern.is_oneway() {
        return Err(PatternProblem::UnsupportedModifier.into());
    } else {
        Ok(())
    }
}

/// Given our PSK modifier, we inject the token at the appropriate place.
fn apply_psk_modifier(patterns: &mut Patterns, n: u8) -> Result<(), Error> {
    let tokens = patterns
        .2
        .get_mut((n as usize).saturating_sub(1))
        .ok_or(Error::Pattern(PatternProblem::InvalidPsk))?;
    if n == 0 {
        tokens.insert(0, Token::Psk(n));
    } else {
        tokens.push(Token::Psk(n));
    }
    Ok(())
}

#[cfg(feature = "hfs")]
fn apply_hfs_modifier(patterns: &mut Patterns) {
    // From the HFS spec, Section 5:
    //
    //     Add an "e1" token directly following the first occurence of "e",
    //     unless there is a DH operation in this same message, in which case
    //     the "hfs" [should be "e1"?] token is placed directly after this DH
    //     (so that the public key will be encrypted).
    //
    //     The "hfs" modifier also adds an "ekem1" token directly following the
    //     first occurrence of "ee".

    // Add the e1 token
    let mut e1_insert_idx = None;
    for msg in patterns.2.iter_mut() {
        if let Some(e_idx) = msg.iter().position(|x| *x == Token::E) {
            if let Some(dh_idx) = msg.iter().position(|x| x.is_dh()) {
                e1_insert_idx = Some(dh_idx + 1);
            } else {
                e1_insert_idx = Some(e_idx + 1);
            }
        }
        if let Some(idx) = e1_insert_idx {
            msg.insert(idx, Token::E1);
            break;
        }
    }

    // Add the ekem1 token
    let mut ee_insert_idx = None;
    for msg in patterns.2.iter_mut() {
        if let Some(ee_idx) = msg.iter().position(|x| *x == Token::Dh(Ee)) {
            ee_insert_idx = Some(ee_idx + 1)
        }
        if let Some(idx) = ee_insert_idx {
            msg.insert(idx, Token::Ekem1);
            break;
        }
    }

    // This should not be possible, because the caller verified that the
    // HandshakePattern is not one-way.
    assert!(
        !(e1_insert_idx.is_some() ^ ee_insert_idx.is_some()),
        "handshake messages contain one of the ['e1', 'ekem1'] tokens, but not the other",
    );
}
