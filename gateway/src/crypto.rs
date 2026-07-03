use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use hkdf::Hkdf;
use zeroize::{Zeroize, Zeroizing};
use x25519_dalek::{EphemeralSecret, PublicKey};
use std::collections::HashMap;

// Cipher types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpCipher {
    Aes256Gcm,
}

// Session keys derived per call
pub struct SrtpKeys {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub tx_salt: [u8; 12],
    pub rx_salt: [u8; 12],
}

impl Zeroize for SrtpKeys {
    fn zeroize(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
        self.tx_salt.zeroize();
        self.rx_salt.zeroize();
    }
}

// Manages the secure channel cryptographic context
pub struct SecureChannelContext {
    pub keys: Option<SrtpKeys>,
    pub peer_fingerprint: Option<String>,
    pub local_secret: Option<EphemeralSecret>,
    pub local_public: Option<PublicKey>,
}

impl Default for SecureChannelContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecureChannelContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureChannelContext")
            .field("keys", &self.keys.is_some())
            .field("peer_fingerprint", &self.peer_fingerprint)
            .finish()
    }
}

impl SecureChannelContext {
    pub fn new() -> Self {
        Self {
            keys: None,
            peer_fingerprint: None,
            local_secret: None,
            local_public: None,
        }
    }

    // Initialize local X25519 ephemeral keypair for PFS
    pub fn initialize_keypair(&mut self) {
        let mut rng = rand::rngs::OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        self.local_secret = Some(secret);
        self.local_public = Some(public);
    }

    pub fn get_local_fingerprint(&self) -> String {
        if let Some(pub_key) = &self.local_public {
            let hash = Sha256::digest(pub_key.as_bytes());
            hex::encode(hash)
        } else {
            "".to_string()
        }
    }

    // Computes the Diffie-Hellman shared secret and derives AES-256-GCM session keys
    pub fn derive_keys(&mut self, peer_public_bytes: [u8; 32], is_server: bool) -> Result<(), &'static str> {
        let secret = self.local_secret.take().ok_or("Local secret key missing")?;
        let peer_public = PublicKey::from(peer_public_bytes);
        
        // ECDH Shared Secret
        let shared_secret = secret.diffie_hellman(&peer_public);
        let shared_bytes = shared_secret.as_bytes();

        // Check fingerprint if configured
        if let Some(expected) = &self.peer_fingerprint {
            let hash = Sha256::digest(peer_public_bytes);
            let actual = hex::encode(hash);
            if actual != *expected {
                return Err("DTLS Fingerprint verification failed! Potential MITM attack.");
            }
        }

        // Key Derivation Function (HKDF-SHA256)
        let hk = Hkdf::<Sha256>::new(None, shared_bytes);
        let mut okm = [0u8; 88]; // 32B TX key + 32B RX key + 12B TX salt + 12B RX salt
        hk.expand(b"Aquilla-12 SRTP AEAD_AES_256_GCM PFS Keying Material", &mut okm)
            .map_err(|_| "HKDF expansion failed")?;

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        let mut tx_salt = [0u8; 12];
        let mut rx_salt = [0u8; 12];

        // Assign keys based on role to prevent key reuse in both directions
        if is_server {
            tx_key.copy_from_slice(&okm[0..32]);
            rx_key.copy_from_slice(&okm[32..64]);
            tx_salt.copy_from_slice(&okm[64..76]);
            rx_salt.copy_from_slice(&okm[76..88]);
        } else {
            rx_key.copy_from_slice(&okm[0..32]);
            tx_key.copy_from_slice(&okm[32..64]);
            rx_salt.copy_from_slice(&okm[64..76]);
            tx_salt.copy_from_slice(&okm[76..88]);
        }

        self.keys = Some(SrtpKeys {
            tx_key,
            rx_key,
            tx_salt,
            rx_salt,
        });

        // Clean up memory
        let mut zero_okm = Zeroizing::new(okm);
        zero_okm.zeroize();

        Ok(())
    }

    pub fn destroy(&mut self) {
        if let Some(mut k) = self.keys.take() {
            k.zeroize();
        }
        self.peer_fingerprint = None;
        self.local_secret = None;
        self.local_public = None;
    }
}

// Encrypts an RTP payload using AES-256-GCM in-place
pub fn encrypt_rtp_gcm(
    keys: &SrtpKeys,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], &'static str> {
    let cipher = Aes256Gcm::new_from_slice(&keys.tx_key).map_err(|_| "Invalid key size")?;
    
    // Construct unique IV/Nonce from salt + SSRC + Sequence Number + Timestamp
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..12].copy_from_slice(&keys.tx_salt);
    
    // XOR with packet headers to create cryptographic variance per packet
    nonce_bytes[0] ^= ((ssrc >> 24) & 0xFF) as u8;
    nonce_bytes[1] ^= ((ssrc >> 16) & 0xFF) as u8;
    nonce_bytes[2] ^= ((ssrc >> 8) & 0xFF) as u8;
    nonce_bytes[3] ^= (ssrc & 0xFF) as u8;
    nonce_bytes[4] ^= ((timestamp >> 24) & 0xFF) as u8;
    nonce_bytes[5] ^= ((timestamp >> 16) & 0xFF) as u8;
    nonce_bytes[6] ^= ((timestamp >> 8) & 0xFF) as u8;
    nonce_bytes[7] ^= (timestamp & 0xFF) as u8;
    nonce_bytes[8] ^= ((sequence_number >> 8) & 0xFF) as u8;
    nonce_bytes[9] ^= (sequence_number & 0xFF) as u8;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Associated Authenticated Data (AAD): RTP Header elements
    let mut aad = Vec::with_capacity(12);
    aad.push(0x80u8); // Version 2
    aad.push(0x00u8); // Payload type 0
    aad.extend_from_slice(&sequence_number.to_be_bytes());
    aad.extend_from_slice(&timestamp.to_be_bytes());
    aad.extend_from_slice(&ssrc.to_be_bytes());

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, payload)
        .map_err(|_| "AES-GCM encryption failed")?;

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_slice());
    Ok(tag_bytes)
}

// Decrypts and authenticates an incoming AES-256-GCM SRTP payload
pub fn decrypt_rtp_gcm(
    keys: &SrtpKeys,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &mut Vec<u8>,
    tag_bytes: &[u8; 16],
) -> Result<(), &'static str> {
    let cipher = Aes256Gcm::new_from_slice(&keys.rx_key).map_err(|_| "Invalid key size")?;
    
    // Construct matching IV/Nonce
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..12].copy_from_slice(&keys.rx_salt);
    
    nonce_bytes[0] ^= ((ssrc >> 24) & 0xFF) as u8;
    nonce_bytes[1] ^= ((ssrc >> 16) & 0xFF) as u8;
    nonce_bytes[2] ^= ((ssrc >> 8) & 0xFF) as u8;
    nonce_bytes[3] ^= (ssrc & 0xFF) as u8;
    nonce_bytes[4] ^= ((timestamp >> 24) & 0xFF) as u8;
    nonce_bytes[5] ^= ((timestamp >> 16) & 0xFF) as u8;
    nonce_bytes[6] ^= ((timestamp >> 8) & 0xFF) as u8;
    nonce_bytes[7] ^= (timestamp & 0xFF) as u8;
    nonce_bytes[8] ^= ((sequence_number >> 8) & 0xFF) as u8;
    nonce_bytes[9] ^= (sequence_number & 0xFF) as u8;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Associated Authenticated Data (AAD)
    let mut aad = Vec::with_capacity(12);
    aad.push(0x80u8);
    aad.push(0x00u8);
    aad.extend_from_slice(&sequence_number.to_be_bytes());
    aad.extend_from_slice(&timestamp.to_be_bytes());
    aad.extend_from_slice(&ssrc.to_be_bytes());

    let tag = Tag::from_slice(tag_bytes);

    cipher
        .decrypt_in_place_detached(nonce, &aad, payload, tag)
        .map_err(|_| "AES-GCM decryption/authentication failed! Integrity breach.")?;

    Ok(())
}

// Argon2id Password Hashing for Government Compliance
pub fn hash_password(password: &str) -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(parsed) => parsed.to_string(),
        Err(_) => "".to_string(),
    }
}

pub fn verify_password(password: &str, hashed: &str) -> bool {
    use argon2::{password_hash::PasswordVerifier, Argon2, PasswordHash};
    
    let parsed_hash = match PasswordHash::new(hashed) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

// RFC 8760 SIP SHA-256 / SHA-512 Digest Authentication
pub fn compute_sip_digest_sha256(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    // HA1 = SHA-256(username:realm:password)
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", username, realm, password).as_bytes());
    let ha1 = hex::encode(hasher.finalize());

    // HA2 = SHA-256(method:uri)
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", method, uri).as_bytes());
    let ha2 = hex::encode(hasher.finalize());

    // Response = SHA-256(HA1:nonce:HA2)
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", ha1, nonce, ha2).as_bytes());
    hex::encode(hasher.finalize())
}

// Generate random API keys
pub fn generate_api_key() -> String {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    hex::encode(key)
}

pub fn parse_key_exchange(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.starts_with(b"AQUILLA12_KEY_EXCHANGE:") {
        let msg = String::from_utf8_lossy(payload);
        let parts: Vec<&str> = msg.split(':').collect();
        if parts.len() >= 3 {
            let pub_key_hex = parts[2].trim();
            if let Ok(bytes) = hex::decode(pub_key_hex) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Some(key);
                }
            }
        }
    }
    None
}

pub fn generate_self_signed_cert() -> Result<(String, String), &'static str> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names).map_err(|_| "Failed to generate cert")?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}
