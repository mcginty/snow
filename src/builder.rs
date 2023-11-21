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
/// # use snow::Builder;
/// # let my_long_term_key = [0u8; 32];
/// # let their_pub_key = [0u8; 32];
/// # #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
/// let noise = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
///     .local_private_key(&my_long_term_key)
///     .remote_public_key(&their_pub_key)
///     .prologue("noise is just swell".as_bytes())
///     .build_initiator()
///     .unwrap();
/// ```
pub struct Builder<'builder> {
    params:   NoiseParams,
    resolver: BoxedCryptoResolver,
    s:        Option<&'builder [u8]>,
    e_fixed:  Option<&'builder [u8]>,
    rs:       Option<&'builder [u8]>,
    psks:     [Option<&'builder [u8]>; 10],
    plog:     Option<&'builder [u8]>,
}

impl<'builder> Builder<'builder> {
    /// Create a Builder with the default crypto resolver.
    #[cfg(all(
        feature = "default-resolver",
        not(any(feature = "ring-accelerated", feature = "libsodium-accelerated"))
    ))]
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
    pub fn with_resolver(params: NoiseParams, resolver: BoxedCryptoResolver) -> Self {
        Builder { params, resolver, s: None, e_fixed: None, rs: None, plog: None, psks: [None; 10] }
    }

    /// Specify a PSK (only used with `NoisePSK` base parameter)
    pub fn psk(mut self, location: u8, key: &'builder [u8]) -> Self {
        self.psks[location as usize] = Some(key);
        self
    }

    /// Your static private key (can be generated with [`generate_keypair()`]).
    ///
    /// [`generate_keypair()`]: #method.generate_keypair
    pub fn local_private_key(mut self, key: &'builder [u8]) -> Self {
        self.s = Some(key);
        self
    }

    #[doc(hidden)]
    pub fn fixed_ephemeral_key_for_testing_only(mut self, key: &'builder [u8]) -> Self {
        self.e_fixed = Some(key);
        self
    }

    /// Arbitrary data to be hashed in to the handshake hash value.
    pub fn prologue(mut self, key: &'builder [u8]) -> Self {
        self.plog = Some(key);
        self
    }

    /// The responder's static public key.
    pub fn remote_public_key(mut self, pub_key: &'builder [u8]) -> Self {
        self.rs = Some(pub_key);
        self
    }

    // TODO: performance issue w/ creating a new RNG and DH instance per call.
    /// Generate a new asymmetric keypair (for use as a static key).
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

    /// Builds an asymmetric [`Keypair`] from a given secret key and specified dh algorithm.
    pub fn build_keypair_from_secret_key(
        &self,
        secret_key: &'builder [u8],
    ) -> Result<Keypair, Error> {
        let mut s_dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        s_dh.set(secret_key);
        Ok(Keypair { private: secret_key.to_vec(), public: s_dh.pubkey().to_vec() })
    }

    /// Build a [`HandshakeState`] for the side who will initiate the handshake (send the first message)
    pub fn build_initiator(self) -> Result<HandshakeState, Error> {
        self.build(true)
    }

    /// Build a [`HandshakeState`] for the side who will be responder (receive the first message)
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
            psks,
            self.plog.unwrap_or(&[]),
            cipherstates,
        )?;
        Self::resolve_kem(self.resolver, &mut hs)?;
        Ok(hs)
    }

    #[cfg(not(feature = "hfs"))]
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

    #[test]
    fn test_builder() {
        let _noise = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .prologue(&[2, 2, 2, 2, 2, 2, 2, 2])
            .local_private_key(&[0u8; 32])
            .build_initiator()
            .unwrap();
    }

    #[test]
    fn test_builder_keygen() {
        let builder = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap());
        let key1 = builder.generate_keypair();
        let key2 = builder.generate_keypair();
        assert!(key1.unwrap() != key2.unwrap());
    }

    #[test]
    fn test_deterministic_keybuild() {
        let public_key = [
            21, 50, 22, 157, 231, 160, 237, 11, 91, 131, 166, 162, 185, 55, 24, 125, 138, 176, 99,
            166, 20, 161, 157, 57, 177, 241, 215, 0, 51, 13, 150, 31,
        ];
        let secret_key = [
            83, 75, 77, 152, 164, 249, 65, 65, 239, 36, 159, 145, 250, 29, 58, 215, 250, 9, 55,
            243, 134, 157, 198, 189, 182, 21, 182, 36, 34, 4, 125, 122,
        ];
        let builder = Builder::new("Noise_NX_25519_AESGCM_BLAKE2s".parse().unwrap());
        let keypair = builder.build_keypair_from_secret_key(&secret_key).unwrap();
        assert_eq!(&keypair.public, &public_key);
    }

    #[test]
    fn test_builder_bad_spec() {
        let params: ::std::result::Result<NoiseParams, _> =
            "Noise_NK_25519_ChaChaPoly_BLAH256".parse();

        if params.is_ok() {
            panic!("NoiseParams should have failed");
        }
    }

    #[test]
    fn test_builder_missing_prereqs() {
        let noise = Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
            .prologue(&[2, 2, 2, 2, 2, 2, 2, 2])
            .local_private_key(&[0u8; 32])
            .build_initiator(); // missing remote key, should result in Err

        if noise.is_ok() {
            panic!("builder should have failed on build");
        }
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
