use protocol_name::*;
use crypto_types::*;
use handshakestate::*;
use wrappers::rand_wrapper::*;
use wrappers::crypto_wrapper::*;
use constants::*;
use cipherstate::*;

trait CryptoResolver {
    fn resolve_rng(&self) -> Option<Box<RandomType>>;
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<DhType>>;
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<HashType>>;
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<CipherStateType>>;
}

struct DefaultResolver;
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

struct NoiseBuilder {
    params: NoiseParams,           // Deserialized protocol spec
    resolver: Box<CryptoResolver>, // The mapper from protocol choices to crypto implementations
    pub rs: [u8; MAXDHLEN],
    pub re: [u8; MAXDHLEN],
    pub has_s: bool,
    pub has_e: bool,
    pub has_rs: bool,
    pub has_re: bool,
}

impl NoiseBuilder {
    pub fn new(params: NoiseParams) -> Result<Self, NoiseError> {
        Self::new_with_resolver(params, Box::new(DefaultResolver{}))
    }

    pub fn new_with_resolver(params: NoiseParams, resolver: Box<CryptoResolver>) -> Result<Self, NoiseError>
    {
        Ok(NoiseBuilder {
            params: params,
            resolver: resolver,
            rs: [0u8; MAXDHLEN],
            re: [0u8; MAXDHLEN],
            has_s: false,
            has_e: false,
            has_rs: false,
            has_re: false,
        })
    }

    fn build(mut self, initiator: bool) -> Result<HandshakeState, NoiseError> {
        let rng = self.resolver.resolve_rng()
            .ok_or(NoiseError::InitError("no suitable RNG"))?;
        let cipher = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;
        let hash = self.resolver.resolve_hash(&self.params.hash)
            .ok_or(NoiseError::InitError("no suitable hash implementation"))?;
        let s = self.resolver.resolve_dh(&self.params.dh)
            .ok_or(NoiseError::InitError("no suitable DH implementation"))?;
        let e = self.resolver.resolve_dh(&self.params.dh)
            .ok_or(NoiseError::InitError("no suitable DH implementation"))?;
        let cipherstate1 = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;
        let cipherstate2 = self.resolver.resolve_cipher(&self.params.cipher)
            .ok_or(NoiseError::InitError("no suitable cipher implementation"))?;
        HandshakeState::new(rng, cipher, hash, s, e,
                            self.rs.to_owned(), self.re.to_owned(),
                            self.has_s, self.has_e, self.has_rs, self.has_re,
                            initiator,
                            self.params.handshake,
                            &[0u8; 0],
                            None,
                            cipherstate1, cipherstate2)
    }

    pub fn build_sender(mut self) -> Result<HandshakeState, NoiseError> {
        self.build(true)
    }

    pub fn build_responder(mut self) -> Result<HandshakeState, NoiseError> {
        self.build(false)
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let noise = NoiseBuilder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap()).unwrap();
    }
}

