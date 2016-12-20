use protocol_name::*;
use crypto_types::*;
use handshakestate::*;
use wrappers::rand_wrapper::*;
use wrappers::crypto_wrapper::*;
use constants::*;
use patterns::*;
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
    pub s:  Vec<u8>,
    pub e:  Vec<u8>,
    pub rs: Vec<u8>,
    pub re: Vec<u8>,
    pub psk: Option<Vec<u8>>,
    pub plog: Option<Vec<u8>>,
    pub has_s: bool,
    pub has_e: bool,
    pub has_rs: bool,
    pub has_re: bool,
}

impl NoiseBuilder {
    pub fn new(params: NoiseParams) -> Self {
        Self::new_with_resolver(params, Box::new(DefaultResolver{}))
    }

    pub fn new_with_resolver(params: NoiseParams, resolver: Box<CryptoResolver>) -> Self
    {
        NoiseBuilder {
            params: params,
            resolver: resolver,
            s: Vec::with_capacity(MAXDHLEN),
            e: Vec::with_capacity(MAXDHLEN),
            rs: Vec::with_capacity(MAXDHLEN),
            re: Vec::with_capacity(MAXDHLEN),
            plog: None,
            psk: None,
            has_s: false,
            has_e: false,
            has_rs: false,
            has_re: false,
        }
    }

    pub fn preshared_key(mut self, key: &[u8]) -> Self {
        self.psk = Some(key.to_vec());
        self
    }

    pub fn needs_local_private_key(&self) -> bool {
        HandshakePattern::needs_local_key(self.params.handshake)
    }

    pub fn local_private_key(mut self, key: &[u8]) -> Self {
        self.s = key.to_vec();
        self.has_s = true;
        self
    }

    pub fn prologue(mut self, key: &[u8]) -> Self {
        self.plog = Some(key.to_vec());
        self
    }

    pub fn needs_remote_public_key(&self) -> bool {
        HandshakePattern::needs_known_remote_key(self.params.handshake)
    }

    pub fn remote_public_key(mut self, pub_key: &[u8]) -> Self {
        self.rs = pub_key.to_vec();
        self.has_rs = true;
        self
    }

    pub fn build_initiator(mut self) -> Result<HandshakeState, NoiseError> {
        self.build(true)
    }

    pub fn build_responder(mut self) -> Result<HandshakeState, NoiseError> {
        self.build(false)
    }

    fn build(mut self, initiator: bool) -> Result<HandshakeState, NoiseError> {
        if !self.has_s && self.needs_local_private_key() {
            return Err(NoiseError::InitError("local key needed for chosen handshake pattern"));
        }

        if !self.has_rs && self.needs_remote_public_key() {
            return Err(NoiseError::InitError("remote key needed for chosen handshake pattern"));
        }

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
                            self.rs, self.re,
                            self.has_s, self.has_e, self.has_rs, self.has_re,
                            initiator,
                            self.params.handshake,
                            &[0u8; 0],
                            None,
                            cipherstate1, cipherstate2)
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let noise = NoiseBuilder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
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

