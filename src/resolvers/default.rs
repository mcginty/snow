#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

// DH
#[cfg(feature = "use-curve25519-dalek")]
use curve25519_dalek::montgomery::MontgomeryPoint;

// Hashes
#[cfg(feature = "use-blake2")]
use blake2::{Blake2b, Blake2b512, Blake2s, Blake2s256, Digest as BlakeDigest};
#[cfg(feature = "use-sha2")]
#[allow(unused)]
// `blake2` and `sha2` both try to export `digest::Digest`.
// We will import those with different aliases to prevent name clashes.
use sha2::{Digest as ShaDigest, Sha256, Sha512};

// Ciphers
#[cfg(feature = "use-chacha20poly1305")]
use chacha20poly1305::ChaCha20Poly1305;
#[cfg(feature = "use-xchacha20poly1305")]
use chacha20poly1305::XChaCha20Poly1305;

#[cfg(any(feature = "use-chacha20poly1305", feature = "use-xchacha20poly1305"))]
use chacha20poly1305::{aead::AeadInPlace, KeyInit};

#[cfg(feature = "use-aes-gcm")]
use aes_gcm::Aes256Gcm;

// PQ
#[cfg(feature = "use-pqcrypto-kyber1024")]
use crate::params::KemChoice;
#[cfg(feature = "use-pqcrypto-kyber1024")]
use crate::types::Kem;
#[cfg(feature = "p256")]
use p256::{self, elliptic_curve::sec1::ToEncodedPoint, EncodedPoint};
#[cfg(feature = "use-pqcrypto-kyber1024")]
use pqcrypto_kyber::kyber1024;
#[cfg(feature = "use-pqcrypto-kyber1024")]
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use super::CryptoResolver;
use crate::{
    constants::{CIPHERKEYLEN, TAGLEN},
    params::{CipherChoice, DHChoice, HashChoice},
    types::{Cipher, Dh, Hash, Random},
    Error,
};
use rand_core::OsRng;

/// The default resolver provided by snow. This resolver is designed to
/// support as many of the Noise spec primitives as possible with
/// pure-Rust (or nearly pure-Rust) implementations.
#[allow(clippy::module_name_repetitions)]
#[derive(Default)]
pub struct DefaultResolver;

impl CryptoResolver for DefaultResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(OsRng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match *choice {
            #[cfg(feature = "use-curve25519-dalek")]
            DHChoice::Curve25519 => Some(Box::<Dh25519>::default()),
            DHChoice::Curve448 => None,
            #[cfg(feature = "p256")]
            DHChoice::P256 => Some(Box::<P256>::default()),
        }
    }

    #[allow(unreachable_patterns)]
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match *choice {
            #[cfg(feature = "use-sha2")]
            HashChoice::SHA256 => Some(Box::<HashSHA256>::default()),
            #[cfg(feature = "use-sha2")]
            HashChoice::SHA512 => Some(Box::<HashSHA512>::default()),
            #[cfg(feature = "use-blake2")]
            HashChoice::Blake2s => Some(Box::<HashBLAKE2s>::default()),
            #[cfg(feature = "use-blake2")]
            HashChoice::Blake2b => Some(Box::<HashBLAKE2b>::default()),
            _ => None,
        }
    }

    #[allow(unreachable_patterns)]
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            #[cfg(feature = "use-chacha20poly1305")]
            CipherChoice::ChaChaPoly => Some(Box::<CipherChaChaPoly>::default()),
            #[cfg(feature = "use-xchacha20poly1305")]
            CipherChoice::XChaChaPoly => Some(Box::new(CipherXChaChaPoly::default())),
            #[cfg(feature = "use-aes-gcm")]
            CipherChoice::AESGCM => Some(Box::<CipherAesGcm>::default()),
            _ => None,
        }
    }

    #[cfg(feature = "use-pqcrypto-kyber1024")]
    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn Kem>> {
        match *choice {
            KemChoice::Kyber1024 => Some(Box::new(Kyber1024::default())),
        }
    }
}

/// Wraps x25519-dalek.
#[cfg(feature = "use-curve25519-dalek")]
#[derive(Default)]
struct Dh25519 {
    privkey: [u8; 32],
    pubkey: [u8; 32],
}

/// Wraps p256
#[cfg(feature = "p256")]
#[derive(Default)]
struct P256 {
    privkey: [u8; 32],
    pubkey: EncodedPoint,
}

/// Wraps `aes-gcm`'s AES256-GCM implementation.
#[cfg(feature = "use-aes-gcm")]
#[derive(Default)]
struct CipherAesGcm {
    key: [u8; CIPHERKEYLEN],
}

/// Wraps `chacha20_poly1305_aead`'s `ChaCha20Poly1305` implementation.
#[cfg(feature = "use-chacha20poly1305")]
#[derive(Default)]
struct CipherChaChaPoly {
    key: [u8; CIPHERKEYLEN],
}

/// Wraps `chachapoly1305`'s XChaCha20Poly1305 implementation.
#[cfg(feature = "use-xchacha20poly1305")]
#[derive(Default)]
struct CipherXChaChaPoly {
    key: [u8; CIPHERKEYLEN],
}

/// Wraps `RustCrypto`'s SHA-256 implementation.
#[cfg(feature = "use-sha2")]
struct HashSHA256 {
    hasher: Sha256,
}

/// Wraps `RustCrypto`'s SHA-512 implementation.
#[cfg(feature = "use-sha2")]
struct HashSHA512 {
    hasher: Sha512,
}

/// Wraps `blake2-rfc`'s implementation.
#[cfg(feature = "use-blake2")]
#[derive(Default)]
struct HashBLAKE2b {
    hasher: Blake2b512,
}

/// Wraps `blake2-rfc`'s implementation.
#[cfg(feature = "use-blake2")]
#[derive(Default)]
struct HashBLAKE2s {
    hasher: Blake2s256,
}

/// Wraps `kyber1024`'s implementation
#[cfg(feature = "use-pqcrypto-kyber1024")]
struct Kyber1024 {
    privkey: kyber1024::SecretKey,
    pubkey: kyber1024::PublicKey,
}

impl Random for OsRng {}

#[cfg(feature = "use-curve25519-dalek")]
impl Dh25519 {
    fn derive_pubkey(&mut self) {
        let point = MontgomeryPoint::mul_base_clamped(self.privkey);
        self.pubkey = point.to_bytes();
    }
}

#[cfg(feature = "use-curve25519-dalek")]
impl Dh for Dh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        let mut bytes = [0u8; CIPHERKEYLEN];
        copy_slices!(privkey, bytes);
        self.privkey = bytes;
        self.derive_pubkey();
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        let mut bytes = [0u8; CIPHERKEYLEN];
        rng.fill_bytes(&mut bytes);
        self.privkey = bytes;
        self.derive_pubkey();
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut pubkey_owned = [0u8; CIPHERKEYLEN];
        copy_slices!(&pubkey[..32], pubkey_owned);
        let result = MontgomeryPoint(pubkey_owned).mul_clamped(self.privkey).to_bytes();
        copy_slices!(result, out);
        Ok(())
    }
}

#[cfg(feature = "p256")]
impl P256 {
    fn derive_pubkey(&mut self) {
        let secret_key = p256::SecretKey::from_bytes(&self.privkey.into()).unwrap();
        let public_key = secret_key.public_key();
        let encoded_pub = public_key.to_encoded_point(false);
        self.pubkey = encoded_pub;
    }
}

#[cfg(feature = "p256")]
impl Dh for P256 {
    fn name(&self) -> &'static str {
        "P256"
    }

    fn pub_len(&self) -> usize {
        65 // Uncompressed SEC-1 encoding
    }

    fn priv_len(&self) -> usize {
        32 // Scalar
    }

    fn dh_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        let mut bytes = [0u8; 32];
        copy_slices!(privkey, bytes);
        self.privkey = bytes;
        self.derive_pubkey();
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        self.privkey = bytes;
        self.derive_pubkey();
    }

    fn pubkey(&self) -> &[u8] {
        self.pubkey.as_bytes()
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let secret_key = p256::SecretKey::from_bytes(&self.privkey.into()).or(Err(Error::Dh))?;
        let secret_key_scalar = secret_key.to_nonzero_scalar();
        let pub_key: p256::elliptic_curve::PublicKey<p256::NistP256> =
            p256::PublicKey::from_sec1_bytes(&pubkey).or(Err(Error::Dh))?;
        let dh_output = p256::ecdh::diffie_hellman(secret_key_scalar, pub_key.as_affine());
        copy_slices!(dh_output.raw_secret_bytes(), out);
        Ok(())
    }
}

#[cfg(feature = "use-aes-gcm")]
impl Cipher for CipherAesGcm {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        copy_slices!(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let aead = Aes256Gcm::new(&self.key.into());

        let mut nonce_bytes = [0u8; 12];
        copy_slices!(nonce.to_be_bytes(), &mut nonce_bytes[4..]);

        copy_slices!(plaintext, out);

        let tag = aead
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[0..plaintext.len()])
            .expect("Encryption failed!");

        copy_slices!(tag, &mut out[plaintext.len()..]);

        plaintext.len() + TAGLEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let aead = aes_gcm::Aes256Gcm::new(&self.key.into());

        let mut nonce_bytes = [0u8; 12];
        copy_slices!(nonce.to_be_bytes(), &mut nonce_bytes[4..]);

        let message_len = ciphertext.len() - TAGLEN;

        copy_slices!(ciphertext[..message_len], out);

        aead.decrypt_in_place_detached(
            &nonce_bytes.into(),
            authtext,
            &mut out[..message_len],
            ciphertext[message_len..].into(),
        )
        .map(|()| message_len)
        .map_err(|_| Error::Decrypt)
    }
}

#[cfg(feature = "use-chacha20poly1305")]
impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        copy_slices!(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(nonce.to_le_bytes(), &mut nonce_bytes[4..]);

        copy_slices!(plaintext, out);

        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[0..plaintext.len()])
            .unwrap();

        copy_slices!(tag, &mut out[plaintext.len()..]);

        plaintext.len() + tag.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(nonce.to_le_bytes(), &mut nonce_bytes[4..]);

        let message_len = ciphertext.len() - TAGLEN;

        copy_slices!(ciphertext[..message_len], out);

        ChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(
                &nonce_bytes.into(),
                authtext,
                &mut out[..message_len],
                ciphertext[message_len..].into(),
            )
            .map_err(|_| Error::Decrypt)?;

        Ok(message_len)
    }
}

#[cfg(feature = "use-xchacha20poly1305")]
impl Cipher for CipherXChaChaPoly {
    fn name(&self) -> &'static str {
        "XChaChaPoly"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        copy_slices!(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 24];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[16..]);

        copy_slices!(plaintext, out);

        let tag = XChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[0..plaintext.len()])
            .unwrap();

        copy_slices!(tag, &mut out[plaintext.len()..]);

        plaintext.len() + tag.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut nonce_bytes = [0u8; 24];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[16..]);

        let message_len = ciphertext.len() - TAGLEN;

        copy_slices!(ciphertext[..message_len], out);

        XChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(
                &nonce_bytes.into(),
                authtext,
                &mut out[..message_len],
                ciphertext[message_len..].into(),
            )
            .map_err(|_| Error::Decrypt)?;

        Ok(message_len)
    }
}

#[cfg(feature = "use-sha2")]
impl Default for HashSHA256 {
    fn default() -> HashSHA256 {
        HashSHA256 { hasher: Sha256::new() }
    }
}

#[cfg(feature = "use-sha2")]
impl Hash for HashSHA256 {
    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        copy_slices!(hash.as_slice(), out);
    }
}

#[cfg(feature = "use-sha2")]
impl Default for HashSHA512 {
    fn default() -> HashSHA512 {
        HashSHA512 { hasher: Sha512::new() }
    }
}

#[cfg(feature = "use-sha2")]
impl Hash for HashSHA512 {
    fn name(&self) -> &'static str {
        "SHA512"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.hasher = Sha512::new();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        copy_slices!(hash.as_slice(), out);
    }
}

#[cfg(feature = "use-blake2")]
impl Hash for HashBLAKE2b {
    fn name(&self) -> &'static str {
        "BLAKE2b"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.hasher = Blake2b::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        out[..64].copy_from_slice(&hash);
    }
}

#[cfg(feature = "use-blake2")]
impl Hash for HashBLAKE2s {
    fn name(&self) -> &'static str {
        "BLAKE2s"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.hasher = Blake2s::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        out[..32].copy_from_slice(&hash);
    }
}

#[cfg(feature = "use-pqcrypto-kyber1024")]
impl Default for Kyber1024 {
    fn default() -> Self {
        Kyber1024 {
            pubkey: kyber1024::PublicKey::from_bytes(&[0; kyber1024::public_key_bytes()]).unwrap(),
            privkey: kyber1024::SecretKey::from_bytes(&[0; kyber1024::secret_key_bytes()]).unwrap(),
        }
    }
}

#[cfg(feature = "use-pqcrypto-kyber1024")]
impl Kem for Kyber1024 {
    fn name(&self) -> &'static str {
        "Kyber1024"
    }

    /// The length in bytes of a public key for this primitive.
    fn pub_len(&self) -> usize {
        kyber1024::public_key_bytes()
    }

    /// The length in bytes the Kem cipherthext for this primitive.
    fn ciphertext_len(&self) -> usize {
        kyber1024::ciphertext_bytes()
    }

    /// Shared secret length in bytes that this Kem encapsulates.
    fn shared_secret_len(&self) -> usize {
        kyber1024::shared_secret_bytes()
    }

    /// Generate a new private key.
    fn generate(&mut self, _rng: &mut dyn Random) {
        // PQClean uses their own random generator
        let (pk, sk) = kyber1024::keypair();
        self.pubkey = pk;
        self.privkey = sk;
    }

    /// Get the public key.
    fn pubkey(&self) -> &[u8] {
        self.pubkey.as_bytes()
    }

    /// Generate a shared secret and encapsulate it using this Kem.
    #[must_use]
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), ()> {
        let pubkey = kyber1024::PublicKey::from_bytes(pubkey).map_err(|_| ())?;
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&pubkey);
        shared_secret_out.copy_from_slice(shared_secret.as_bytes());
        ciphertext_out.copy_from_slice(ciphertext.as_bytes());
        Ok((shared_secret.as_bytes().len(), ciphertext.as_bytes().len()))
    }

    /// Decapsulate a ciphertext producing a shared secret.
    #[must_use]
    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, ()> {
        let ciphertext = kyber1024::Ciphertext::from_bytes(ciphertext).map_err(|_| ())?;
        let shared_secret = kyber1024::decapsulate(&ciphertext, &self.privkey);
        shared_secret_out.copy_from_slice(shared_secret.as_bytes());
        Ok(shared_secret.as_bytes().len())
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    #[test]
    #[cfg(feature = "use-sha2")]
    fn test_sha256() {
        let mut output = [0u8; 32];
        let mut hasher = HashSHA256::default();
        hasher.input(b"abc");
        hasher.result(&mut output);
        assert!(
            hex::encode(output)
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    #[cfg(feature = "use-sha2")]
    fn test_hmac_sha256_sha512() {
        let key = Vec::<u8>::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = Vec::<u8>::from_hex(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();
        let mut output1 = [0u8; 32];
        let mut hasher = HashSHA256::default();
        hasher.hmac(&key, &data, &mut output1);
        assert!(
            hex::encode(output1)
                == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );

        let mut output2 = [0u8; 64];
        let mut hasher = HashSHA512::default();
        hasher.hmac(&key, &data, &mut output2);
        assert!(
            hex::encode(output2)
                == "fa73b0089d56a284efb0f0756c890be9\
                                     b1b5dbdd8ee81a3655f83e33b2279d39\
                                     bf3e848279a722c806b485a47e67c807\
                                     b946a337bee8942674278859e13292fb"
        );
    }

    #[test]
    #[cfg(feature = "use-blake2")]
    fn test_blake2b() {
        // BLAKE2b test - draft-saarinen-blake2-06
        let mut output = [0u8; 64];
        let mut hasher = HashBLAKE2b::default();
        hasher.input(b"abc");
        hasher.result(&mut output);
        assert!(
            hex::encode(output)
                == "ba80a53f981c4d0d6a2797b69f12f6e9\
                                    4c212f14685ac4b74b12bb6fdbffa2d1\
                                    7d87c5392aab792dc252d5de4533cc95\
                                    18d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    #[cfg(feature = "use-blake2")]
    fn test_blake2s() {
        // BLAKE2s test - draft-saarinen-blake2-06
        let mut output = [0u8; 32];
        let mut hasher = HashBLAKE2s::default();
        hasher.input(b"abc");
        hasher.result(&mut output);
        assert!(
            hex::encode(output)
                == "508c5e8c327c14e2e1a72ba34eeb452f\
                    37458b209ed63a294d999b4c86675982"
        );
    }

    #[test]
    #[cfg(feature = "use-curve25519-dalek")]
    fn test_curve25519() {
        // Curve25519 test - draft-curves-10
        let mut keypair = Dh25519::default();
        let scalar =
            Vec::<u8>::from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .unwrap();
        keypair.set(&scalar);
        let public =
            Vec::<u8>::from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
                .unwrap();
        let mut output = [0u8; 32];
        keypair.dh(&public, &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    #[cfg(feature = "p256")]
    fn test_p256() {
        // Test vector from RFC 5903, section 8.1
        let mut keypair = P256::default();
        let scalar =
            Vec::<u8>::from_hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
                .unwrap();
        keypair.set(&scalar);
        // Public key is prefixed with 0x04, to indicate uncompressed form, as per SEC1 encoding
        let public = Vec::<u8>::from_hex(
            "04\
                D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63\
                56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        )
        .unwrap();
        let mut output = [0u8; 32];
        keypair.dh(&public, &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE".to_lowercase()
        );
    }

    #[test]
    #[cfg(feature = "use-aes-gcm")]
    fn test_aesgcm() {
        // AES256-GCM tests - gcm-spec.pdf
        // Test Case 13
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        let mut cipher1 = CipherAesGcm::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);
        assert!(hex::encode(ciphertext) == "530f8afbc74536b9a963b4f1c4cb738b");

        let mut resulttext = [0u8; 1];
        let mut cipher2 = CipherAesGcm::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(resulttext[0] == 0);
        ciphertext[0] ^= 1;
        assert!(cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).is_err());

        // Test Case 14
        let plaintext2 = [0u8; 16];
        let mut ciphertext2 = [0u8; 32];
        let mut cipher3 = CipherAesGcm::default();
        cipher3.set(&key);
        cipher3.encrypt(nonce, &authtext, &plaintext2, &mut ciphertext2);
        assert!(
            hex::encode(ciphertext2)
                == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );

        let mut resulttext2 = [1u8; 16];
        let mut cipher4 = CipherAesGcm::default();
        cipher4.set(&key);
        cipher4.decrypt(nonce, &authtext, &ciphertext2, &mut resulttext2).unwrap();
        assert!(plaintext2 == resulttext2);
        ciphertext2[0] ^= 1;
        assert!(cipher4.decrypt(nonce, &authtext, &ciphertext2, &mut resulttext2).is_err());
    }

    #[test]
    #[cfg(feature = "use-chacha20poly1305")]
    fn test_chachapoly_empty() {
        //ChaChaPoly round-trip test, empty plaintext
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        let mut cipher1 = CipherChaChaPoly::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 1];
        let mut cipher2 = CipherChaChaPoly::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(resulttext[0] == 0);
        ciphertext[0] ^= 1;
        assert!(cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).is_err());
    }

    #[test]
    #[cfg(feature = "use-chacha20poly1305")]
    fn test_chachapoly_nonempty() {
        //ChaChaPoly round-trip test, non-empty plaintext
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0x34u8; 117];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 133];
        let mut cipher1 = CipherChaChaPoly::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 117];
        let mut cipher2 = CipherChaChaPoly::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(hex::encode(resulttext) == hex::encode(plaintext));
    }

    #[test]
    #[cfg(feature = "use-xchacha20poly1305")]
    fn test_xchachapoly_nonempty() {
        //XChaChaPoly round-trip test, non-empty plaintext
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0x34u8; 117];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 133];
        let mut cipher1 = CipherXChaChaPoly::default();
        cipher1.set(&key);
        cipher1.encrypt(nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 117];
        let mut cipher2 = CipherXChaChaPoly::default();
        cipher2.set(&key);
        cipher2.decrypt(nonce, &authtext, &ciphertext, &mut resulttext).unwrap();
        assert!(hex::encode(resulttext.to_vec()) == hex::encode(plaintext.to_vec()));
    }

    #[test]
    #[cfg(feature = "use-chacha20poly1305")]
    fn test_chachapoly_known_answer() {
        //ChaChaPoly known-answer test - RFC 7539
        let key = <[u8; 32]>::from_hex(
            "1c9240a5eb55d38af333888604f6b5f0\
                  473917c1402b80099dca5cbc207075c0",
        )
        .unwrap();
        let nonce = 0x0807_0605_0403_0201_u64;
        let ciphertext = Vec::<u8>::from_hex(
            "64a0861575861af460f062c79be643bd\
                         5e805cfd345cf389f108670ac76c8cb2\
                         4c6cfc18755d43eea09ee94e382d26b0\
                         bdb7b73c321b0100d4f03b7f355894cf\
                         332f830e710b97ce98c8a84abd0b9481\
                         14ad176e008d33bd60f982b1ff37c855\
                         9797a06ef4f0ef61c186324e2b350638\
                         3606907b6a7c02b0f9f6157b53c867e4\
                         b9166c767b804d46a59b5216cde7a4e9\
                         9040c5a40433225ee282a1b0a06c523e\
                         af4534d7f83fa1155b0047718cbc546a\
                         0d072b04b3564eea1b422273f548271a\
                         0bb2316053fa76991955ebd63159434e\
                         cebb4e466dae5a1073a6727627097a10\
                         49e617d91d361094fa68f0ff77987130\
                         305beaba2eda04df997b714d6c6f2c29\
                         a6ad5cb4022b02709b",
        )
        .unwrap();
        let tag = Vec::<u8>::from_hex("eead9d67890cbb22392336fea1851f38").unwrap();
        let authtext = Vec::<u8>::from_hex("f33388860000000000004e91").unwrap();
        let mut combined_text = [0u8; 1024];
        let mut out = [0u8; 1024];
        copy_slices!(&ciphertext, &mut combined_text);
        copy_slices!(&tag[0..TAGLEN], &mut combined_text[ciphertext.len()..]);

        let mut cipher = CipherChaChaPoly::default();
        cipher.set(&key);
        cipher
            .decrypt(
                nonce,
                &authtext,
                &combined_text[..ciphertext.len() + TAGLEN],
                &mut out[..ciphertext.len()],
            )
            .unwrap();
        let desired_plaintext = "496e7465726e65742d44726166747320\
                                 61726520647261667420646f63756d65\
                                 6e74732076616c696420666f72206120\
                                 6d6178696d756d206f6620736978206d\
                                 6f6e74687320616e64206d6179206265\
                                 20757064617465642c207265706c6163\
                                 65642c206f72206f62736f6c65746564\
                                 206279206f7468657220646f63756d65\
                                 6e747320617420616e792074696d652e\
                                 20497420697320696e617070726f7072\
                                 6961746520746f2075736520496e7465\
                                 726e65742d4472616674732061732072\
                                 65666572656e6365206d617465726961\
                                 6c206f7220746f206369746520746865\
                                 6d206f74686572207468616e20617320\
                                 2fe2809c776f726b20696e2070726f67\
                                 726573732e2fe2809d";
        assert!(hex::encode(&out[..ciphertext.len()]) == desired_plaintext);
    }

    #[test]
    #[cfg(feature = "use-pqcrypto-kyber1024")]
    fn test_kyber1024() {
        let mut rng = OsRng::default();
        let mut kem_1 = Kyber1024::default();
        let kem_2 = Kyber1024::default();

        let mut shared_secret_1 = vec![0; kem_1.shared_secret_len()];
        let mut shared_secret_2 = vec![0; kem_2.shared_secret_len()];
        let mut ciphertext = vec![0; kem_1.ciphertext_len()];

        kem_1.generate(&mut rng);
        let (ss1_len, ct_len) =
            kem_2.encapsulate(kem_1.pubkey(), &mut shared_secret_1, &mut ciphertext).unwrap();
        let ss2_len = kem_1.decapsulate(&mut ciphertext, &mut shared_secret_2).unwrap();

        assert_eq!(shared_secret_1, shared_secret_2);
        assert_eq!(ss1_len, shared_secret_1.len());
        assert_eq!(ss2_len, shared_secret_2.len());
        assert_eq!(ss1_len, ss2_len);
        assert_eq!(ct_len, ciphertext.len());
    }

    #[test]
    #[cfg(feature = "use-pqcrypto-kyber1024")]
    fn test_kyber1024_fail() {
        let mut rng = OsRng::default();
        let mut kem_1 = Kyber1024::default();
        let kem_2 = Kyber1024::default();

        let mut shared_secret_1 = vec![0; kem_1.shared_secret_len()];
        let mut shared_secret_2 = vec![0; kem_2.shared_secret_len()];
        let mut ciphertext = vec![0; kem_1.ciphertext_len()];
        let mut bad_ciphertext = vec![0; kem_1.ciphertext_len()];

        kem_1.generate(&mut rng);
        let (ss1_len, ct_len) =
            kem_2.encapsulate(kem_1.pubkey(), &mut shared_secret_1, &mut ciphertext).unwrap();
        let ss2_len = kem_1.decapsulate(&mut bad_ciphertext, &mut shared_secret_2).unwrap();

        assert_ne!(shared_secret_1, shared_secret_2);
        assert_eq!(ss1_len, shared_secret_1.len());
        assert_eq!(ss2_len, shared_secret_2.len());
        assert_eq!(ss1_len, ss2_len);
        assert_eq!(ct_len, ciphertext.len());
    }
}
