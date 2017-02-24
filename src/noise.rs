use constants::*;
use protocol_name::*;
use crypto_types::*;
use handshakestate::*;
use wrappers::rand_wrapper::*;
use wrappers::crypto_wrapper::*;
use cipherstate::*;
use session::*;
use utils::*;

pub trait CryptoResolver {
    fn resolve_rng(&self) -> Option<Box<RandomType>>;
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<DhType>>;
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<HashType>>;
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<CipherStateType>>;
}

pub struct DefaultResolver;
impl CryptoResolver for DefaultResolver {
    fn resolve_rng(&self) -> Option<Box<RandomType>> {
        Some(Box::new(RandomOs::default()))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<DhType>> {
        match *choice {
            DHChoice::Curve25519 => Some(Box::new(Dh25519::default())),
            _                    => None,

        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<HashType>> {
        match *choice {
            HashChoice::SHA256  => Some(Box::new(HashSHA256::default())),
            HashChoice::SHA512  => Some(Box::new(HashSHA512::default())),
            HashChoice::Blake2s => Some(Box::new(HashBLAKE2s::default())),
            HashChoice::Blake2b => Some(Box::new(HashBLAKE2b::default())),
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<CipherStateType>> {
        match *choice {
            CipherChoice::ChaChaPoly => Some(Box::new(CipherState::<CipherChaChaPoly>::default())),
            CipherChoice::AESGCM     => Some(Box::new(CipherState::<CipherAESGCM>::default())),
        }
    }
}

pub struct NoiseBuilder<'a> {
    params: NoiseParams,           // Deserialized protocol spec
    resolver: Box<CryptoResolver>, // The mapper from protocol choices to crypto implementations
    pub s: Option<&'a [u8]>,
    pub e: Option<&'a [u8]>,
    pub rs: Option<Vec<u8>>,
    pub re: Option<Vec<u8>>,
    pub psk: Option<Vec<u8>>,
    pub plog: Option<Vec<u8>>,
}

impl<'a> NoiseBuilder<'a> {
    pub fn new(params: NoiseParams) -> Self {
        Self::with_resolver(params, Box::new(DefaultResolver{}))
    }

    pub fn with_resolver(params: NoiseParams, resolver: Box<CryptoResolver>) -> Self
    {
        NoiseBuilder {
            params: params,
            resolver: resolver,
            s: None,
            e: None,
            rs: None,
            re: None,
            plog: None,
            psk: None,
        }
    }

    pub fn preshared_key(mut self, key: &[u8]) -> Self {
        self.psk = Some(key.to_vec());
        self
    }

    pub fn local_private_key(mut self, key: &'a [u8]) -> Self {
        self.s = Some(key);
        self
    }

    pub fn prologue(mut self, key: &[u8]) -> Self {
        self.plog = Some(key.to_vec());
        self
    }

    pub fn remote_public_key(mut self, pub_key: &[u8]) -> Self {
        self.rs = Some(pub_key.to_vec());
        self
    }

    pub fn build_initiator(self) -> Result<NoiseSession<HandshakeState>, NoiseError> {
        self.build(true)
    }

    pub fn build_responder(self) -> Result<NoiseSession<HandshakeState>, NoiseError> {
        self.build(false)
    }

    fn build(self, initiator: bool) -> Result<NoiseSession<HandshakeState>, NoiseError> {
        if !self.s.is_some() && self.params.handshake.needs_local_static_key(initiator) {
            return Err(NoiseError::InitError("local key needed for chosen handshake pattern"));
        }

        if !self.rs.is_some() && self.params.handshake.need_known_remote_pubkey(initiator) {
            return Err(NoiseError::InitError("remote key needed for chosen handshake pattern"));
        }

        let rng = self.resolver.resolve_rng()
            .ok_or(NoiseError::InitError("no suitable RNG"))?;
        let cipher = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;
        let hash = self.resolver.resolve_hash(&self.params.hash)
            .ok_or(NoiseError::InitError("no suitable hash implementation"))?;
        let mut s_dh = self.resolver.resolve_dh(&self.params.dh)
            .ok_or(NoiseError::InitError("no suitable DH implementation"))?;
        let mut e_dh = self.resolver.resolve_dh(&self.params.dh)
            .ok_or(NoiseError::InitError("no suitable DH implementation"))?;
        let cipherstate1 = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;
        let cipherstate2 = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;

        let s = match self.s {
            Some(k) => {
                (&mut *s_dh).set(k);
                Toggle::on(s_dh)
            },
            None => {
                Toggle::off(s_dh)
            }
        };

        let e = match self.e {
            Some(k) => {
                (&mut *e_dh).set(k);
                Toggle::on(e_dh)
            },
            None => {
                Toggle::off(e_dh)
            }
        };

        let mut rs_buf = [0u8; MAXDHLEN];
        let rs = match self.rs {
            Some(v) => {
                rs_buf[..v.len()].copy_from_slice(&v[..]);
                Toggle::on(rs_buf)
            },
            None => Toggle::off(rs_buf),
        };

        let mut re_buf = [0u8; MAXDHLEN];
        let re = match self.re {
            Some(v) => {
                re_buf[..v.len()].copy_from_slice(&v[..]);
                Toggle::on(re_buf)
            },
            None => Toggle::off(re_buf),
        };

        let hs = HandshakeState::new(rng, cipher, hash,
                                     s, e, rs, re,
                                     initiator,
                                     self.params.handshake,
                                     &[0u8; 0],
                                     None,
                                     CipherStates::new(cipherstate1, cipherstate2)?)?;
        Ok(hs.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let _noise = NoiseBuilder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .preshared_key(&[1,1,1,1,1,1,1])
            .prologue(&[2,2,2,2,2,2,2,2])
            .local_private_key(&[0u8; 32])
            .build_initiator().unwrap();
    }

    #[test]
    fn test_builder_bad_spec() {
        let params: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly_BLAH256".parse();

        if let Ok(_) = params {
            panic!("NoiseParams should have failed");
        }
    }

    #[test]
    fn test_builder_missing_prereqs() {
        let noise = NoiseBuilder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
            .preshared_key(&[1,1,1,1,1,1,1])
            .prologue(&[2,2,2,2,2,2,2,2])
            .local_private_key(&[0u8; 32])
            .build_initiator(); // missing remote key, should result in Err

        if let Ok(_) = noise {
            panic!("builder should have failed on build");
        }
    }
}

