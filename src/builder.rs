use core::fmt::Debug;

#[cfg(feature = "hfs")]
use crate::params::HandshakeModifier;
use crate::{
    cipherstate::{CipherState, CipherStates},
    constants::{MAXDHLEN, PSKLEN},
    error::{Error, InitStage, Prerequisite},
    handshakestate::HandshakeState,
    params::NoiseParams,
    resolvers::{BoxedCryptoResolver, CryptoResolver},
    utils::Toggle,
};
use subtle::ConstantTimeEq;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

/// The maximum number of PSKs we will allocate for.
const MAX_PSKS: usize = 10;

/// A keypair object returned by [`Builder::generate_keypair()`]
///
/// [`generate_keypair()`]: #method.generate_keypair
pub struct Keypair {
    /// The private asymmetric key
    pub private: Vec<u8>,
    /// The public asymmetric key
    pub public:  Vec<u8>,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Keypair) -> bool {
        let priv_eq = self.private.ct_eq(&other.private);
        let pub_eq = self.public.ct_eq(&other.public);

        (priv_eq & pub_eq).into()
    }
}

/// Generates a [`HandshakeState`] and also validates that all the prerequisites for
/// the given parameters are satisfied.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use snow::Builder;
/// # let my_long_term_key = [0u8; 32];
/// # let their_pub_key = [0u8; 32];
/// # #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
/// let noise = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?)
///     .local_private_key(&my_long_term_key)?
///     .remote_public_key(&their_pub_key)?
///     .prologue("noise is just swell".as_bytes())?
///     .build_initiator()?;
/// # Ok(())
/// # }
/// ```
pub struct Builder<'builder> {
    params:   NoiseParams,
    resolver: BoxedCryptoResolver,
    s:        Option<&'builder [u8]>,
    e_fixed:  Option<&'builder [u8]>,
    rs:       Option<&'builder [u8]>,
    psks:     [Option<&'builder [u8; 32]>; MAX_PSKS],
    plog:     Option<&'builder [u8]>,
}

impl<'builder> Debug for Builder<'builder> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Builder").field("params", &self.params.name).finish_non_exhaustive()
    }
}

impl<'builder> Builder<'builder> {
    /// Create a Builder with the default crypto resolver.
    #[cfg(all(
        feature = "default-resolver",
        not(any(feature = "ring-accelerated", feature = "libsodium-accelerated"))
    ))]
    #[must_use]
    pub fn new(params: NoiseParams) -> Self {
        use crate::resolvers::DefaultResolver;

        Self::with_resolver(params, Box::new(DefaultResolver))
    }

    /// Create a Builder with the ring resolver and default resolver as a fallback.
    #[cfg(all(not(feature = "libsodium-accelerated"), feature = "ring-accelerated"))]
    pub fn new(params: NoiseParams) -> Self {
        use crate::resolvers::{DefaultResolver, FallbackResolver, RingResolver};

        Self::with_resolver(
            params,
            Box::new(FallbackResolver::new(Box::new(RingResolver), Box::new(DefaultResolver))),
        )
    }

    /// Create a Builder with the ring resolver and default resolver as a fallback.
    #[cfg(all(not(feature = "ring-accelerated"), feature = "libsodium-accelerated"))]
    pub fn new(params: NoiseParams) -> Self {
        use crate::resolvers::{DefaultResolver, FallbackResolver, SodiumResolver};

        Self::with_resolver(
            params,
            Box::new(FallbackResolver::new(Box::new(SodiumResolver), Box::new(DefaultResolver))),
        )
    }

    /// Create a Builder with a custom crypto resolver.
    #[must_use]
    pub fn with_resolver(params: NoiseParams, resolver: BoxedCryptoResolver) -> Self {
        Builder { params, resolver, s: None, e_fixed: None, rs: None, plog: None, psks: [None; 10] }
    }

    /// Specify a PSK (only used with `NoisePSK` base parameter)
    ///
    /// # Errors
    /// * `InitError(InitStage::ValidatePskPosition)` if the location is a number larger than
    ///   allowed.
    /// * `InitError(InitStage::ParameterOverwrite)` if this method has been called previously.
    pub fn psk(mut self, location: u8, key: &'builder [u8; PSKLEN]) -> Result<Self, Error> {
        let location = location as usize;
        if location >= MAX_PSKS {
            Err(InitStage::ValidatePskPosition.into())
        } else if self.psks[location].is_some() {
            Err(InitStage::ParameterOverwrite.into())
        } else {
            self.psks[location] = Some(key);
            Ok(self)
        }
    }

    /// Your static private key (can be generated with [`generate_keypair()`]).
    ///
    /// [`generate_keypair()`]: #method.generate_keypair
    ///
    /// # Errors
    /// * `InitError(InitStage::ParameterOverwrite)` if this method has been called previously.
    pub fn local_private_key(mut self, key: &'builder [u8]) -> Result<Self, Error> {
        if self.s.is_some() {
            Err(InitStage::ParameterOverwrite.into())
        } else {
            self.s = Some(key);
            Ok(self)
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn fixed_ephemeral_key_for_testing_only(mut self, key: &'builder [u8]) -> Self {
        self.e_fixed = Some(key);
        self
    }

    /// Arbitrary data to be hashed in to the handshake hash value.
    ///
    /// This may only be set once
    ///
    /// # Errors
    /// * `InitError(InitStage::ParameterOverwrite)` if this method has been called previously.
    pub fn prologue(mut self, key: &'builder [u8]) -> Result<Self, Error> {
        if self.plog.is_some() {
            Err(InitStage::ParameterOverwrite.into())
        } else {
            self.plog = Some(key);
            Ok(self)
        }
    }

    /// The responder's static public key.
    ///
    /// # Errors
    /// * `InitError(InitStage::ParameterOverwrite)` if this method has been called previously.
    pub fn remote_public_key(mut self, pub_key: &'builder [u8]) -> Result<Self, Error> {
        if self.rs.is_some() {
            Err(InitStage::ParameterOverwrite.into())
        } else {
            self.rs = Some(pub_key);
            Ok(self)
        }
    }

    // TODO: performance issue w/ creating a new RNG and DH instance per call.
    /// Generate a new asymmetric keypair (for use as a static key).
    ///
    /// # Errors
    /// * `InitError(InitStage::GetRngImpl)` if the RNG implementation failed to resolve.
    /// * `InitError(InitStage::GetDhImpl)` if the DH implementation failed to resolve.
    pub fn generate_keypair(&self) -> Result<Keypair, Error> {
        let mut rng = self.resolver.resolve_rng().ok_or(InitStage::GetRngImpl)?;
        let mut dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let mut private = vec![0u8; dh.priv_len()];
        let mut public = vec![0u8; dh.pub_len()];
        dh.generate(&mut *rng);

        private.copy_from_slice(dh.privkey());
        public.copy_from_slice(dh.pubkey());

        Ok(Keypair { private, public })
    }

    /// Build a [`HandshakeState`] for the side who will initiate the handshake (send the first message)
    ///
    /// # Errors
    /// * `InitError(InitStage::GetRngImpl)` if the RNG implementation failed to resolve.
    /// * `InitError(InitStage::GetDhImpl)` if the DH implementation failed to resolve.
    pub fn build_initiator(self) -> Result<HandshakeState, Error> {
        self.build(true)
    }

    /// Build a [`HandshakeState`] for the side who will be responder (receive the first message)
    ///
    /// # Errors
    /// An `InitError(InitStage)` variant will be returned for various issues in the building of a
    /// usable `HandshakeState`. See `InitStage` for further details.
    pub fn build_responder(self) -> Result<HandshakeState, Error> {
        self.build(false)
    }

    fn build(self, initiator: bool) -> Result<HandshakeState, Error> {
        if self.s.is_none() && self.params.handshake.pattern.needs_local_static_key(initiator) {
            return Err(Prerequisite::LocalPrivateKey.into());
        }

        if self.rs.is_none() && self.params.handshake.pattern.need_known_remote_pubkey(initiator) {
            return Err(Prerequisite::RemotePublicKey.into());
        }

        let rng = self.resolver.resolve_rng().ok_or(InitStage::GetRngImpl)?;
        let cipher =
            self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let hash = self.resolver.resolve_hash(&self.params.hash).ok_or(InitStage::GetHashImpl)?;
        let mut s_dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let mut e_dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let cipher1 =
            self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let cipher2 =
            self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let handshake_cipherstate = CipherState::new(cipher);
        let cipherstates = CipherStates::new(CipherState::new(cipher1), CipherState::new(cipher2))?;

        let s = match self.s {
            Some(k) => {
                (*s_dh).set(k);
                Toggle::on(s_dh)
            },
            None => Toggle::off(s_dh),
        };

        if let Some(fixed_k) = self.e_fixed {
            (*e_dh).set(fixed_k);
        }
        let e = Toggle::off(e_dh);

        let mut rs_buf = [0u8; MAXDHLEN];
        let rs = match self.rs {
            Some(v) => {
                rs_buf[..v.len()].copy_from_slice(v);
                Toggle::on(rs_buf)
            },
            None => Toggle::off(rs_buf),
        };

        let re = Toggle::off([0u8; MAXDHLEN]);

        let mut psks = [None::<[u8; PSKLEN]>; 10];
        for (i, psk) in self.psks.iter().enumerate() {
            if let Some(key) = *psk {
                if key.len() != PSKLEN {
                    return Err(InitStage::ValidatePskLengths.into());
                }
                let mut k = [0u8; PSKLEN];
                k.copy_from_slice(key);
                psks[i] = Some(k);
            }
        }

        let mut hs = HandshakeState::new(
            rng,
            handshake_cipherstate,
            hash,
            s,
            e,
            self.e_fixed.is_some(),
            rs,
            re,
            initiator,
            self.params,
            &psks,
            self.plog.unwrap_or(&[]),
            cipherstates,
        )?;
        Self::resolve_kem(self.resolver, &mut hs)?;
        Ok(hs)
    }

    #[cfg(not(feature = "hfs"))]
    #[allow(clippy::unnecessary_wraps)]
    fn resolve_kem(_: Box<dyn CryptoResolver>, _: &mut HandshakeState) -> Result<(), Error> {
        // HFS is disabled, return nothing
        Ok(())
    }

    #[cfg(feature = "hfs")]
    fn resolve_kem(
        resolver: Box<dyn CryptoResolver>,
        hs: &mut HandshakeState,
    ) -> Result<(), Error> {
        if hs.params.handshake.modifiers.list.contains(&HandshakeModifier::Hfs) {
            if let Some(kem_choice) = hs.params.kem {
                let kem = resolver.resolve_kem(&kem_choice).ok_or(InitStage::GetKemImpl)?;
                hs.set_kem(kem);
            } else {
                return Err(InitStage::GetKemImpl.into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_builder() -> TestResult {
        let _noise = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse()?)
            .prologue(&[2, 2, 2, 2, 2, 2, 2, 2])?
            .local_private_key(&[0u8; 32])?
            .build_initiator()?;
        Ok(())
    }

    #[test]
    fn test_builder_keygen() -> TestResult {
        let builder = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse()?);
        let key1 = builder.generate_keypair();
        let key2 = builder.generate_keypair();
        assert!(key1? != key2?);
        Ok(())
    }

    #[test]
    fn test_builder_bad_spec() {
        let params: ::std::result::Result<NoiseParams, _> =
            "Noise_NK_25519_ChaChaPoly_BLAH256".parse();

        assert!(params.is_err(), "NoiseParams should have failed");
    }

    #[test]
    fn test_builder_missing_prereqs() -> TestResult {
        let noise = Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse()?)
            .prologue(&[2, 2, 2, 2, 2, 2, 2, 2])?
            .local_private_key(&[0u8; 32])?
            .build_initiator(); // missing remote key, should result in Err

        assert!(noise.is_err(), "builder should have failed on build");
        Ok(())
    }

    #[test]
    fn test_builder_param_overwrite() -> TestResult {
        fn build_builder<'a>() -> Result<Builder<'a>, Error> {
            Builder::new("Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse()?)
                .prologue(&[2u8; 10])?
                .psk(0, &[0u8; 32])?
                .local_private_key(&[0u8; 32])?
                .remote_public_key(&[1u8; 32])
        }

        assert_eq!(
            build_builder()?.prologue(&[1u8; 10]).unwrap_err(),
            Error::Init(InitStage::ParameterOverwrite)
        );
        assert!(build_builder()?.psk(1, &[1u8; 32]).is_ok());
        assert_eq!(
            build_builder()?.psk(0, &[1u8; 32]).unwrap_err(),
            Error::Init(InitStage::ParameterOverwrite)
        );
        assert_eq!(
            build_builder()?.local_private_key(&[1u8; 32]).unwrap_err(),
            Error::Init(InitStage::ParameterOverwrite)
        );
        assert_eq!(
            build_builder()?.remote_public_key(&[1u8; 32]).unwrap_err(),
            Error::Init(InitStage::ParameterOverwrite)
        );
        Ok(())
    }

    #[test]
    fn test_partialeq_impl() {
        let keypair_1 = Keypair { private: vec![0x01; 32], public: vec![0x01; 32] };

        let mut keypair_2 = Keypair { private: vec![0x01; 32], public: vec![0x01; 32] };

        // If both private and public are the same, return true
        assert!(keypair_1 == keypair_2);

        // If either public or private are different, return false

        // Wrong private
        keypair_2.private = vec![0x50; 32];
        assert!(keypair_1 != keypair_2);
        // Reset to original
        keypair_2.private = vec![0x01; 32];
        // Wrong public
        keypair_2.public = vec![0x50; 32];
        assert!(keypair_1 != keypair_2);
    }
}
